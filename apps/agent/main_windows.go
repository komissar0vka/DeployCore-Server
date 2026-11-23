package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "DeployCoreAgent"
const exeName = "deploycore-agent.exe"

type eventWriter struct{ target *eventlog.Log }

func (w eventWriter) Write(data []byte) (int, error) {
	return len(data), w.target.Info(1, strings.TrimSpace(string(data)))
}

type serviceHandler struct{}

func (serviceHandler) Execute(_ []string, changes <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending, WaitHint: 5000}
	eventTarget, err := eventlog.Open(serviceName)
	if err != nil {
		return true, 1
	}
	defer eventTarget.Close()
	logger := log.New(eventWriter{eventTarget}, "", 0)
	directory, err := agentDirectory()
	if err != nil {
		logger.Print(err)
		return true, 2
	}
	state, err := loadState(directory)
	if err != nil {
		logger.Printf("Load agent state: %v", err)
		return true, 2
	}
	client, err := newClient(state.Server, state.CA)
	if err != nil {
		logger.Printf("Configure HTTPS client: %v", err)
		return true, 2
	}

	runner := Runner{
		client: client, state: state, save: func(value State) error { return saveState(directory, value) },
		heartbeat: collectHeartbeat, inventory: collectInventory, log: logger,
		jobs: func(ctx context.Context, state State) {
			path := filepath.Join(directory, "deployment.dpapi")
			var journal JobJournal
			if err := loadProtectedJSON(path, &journal); err != nil && !errors.Is(err, os.ErrNotExist) {
				logger.Printf("Load deployment journal: %v", err)
				return
			}
			transport := JobTransport{client: client, state: state, journal: journal, log: logger,
				save: func(value JobJournal) error { return saveProtectedJSON(path, value) }, execute: windowsExecutor(directory)}
			transport.run(ctx)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); runner.run(ctx) }()
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- running
	logger.Printf("Service started, version %s", version)
	for {
		select {
		case change, ok := <-changes:
			if !ok || change.Cmd == svc.Stop || change.Cmd == svc.Shutdown {
				statuses <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				<-done
				logger.Print("Service stopped")
				return false, 0
			}
			if change.Cmd == svc.Interrogate {
				statuses <- running
			}
		case <-done:
			return true, 3
		}
	}
}

func readEnrollmentToken() (string, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	clear(data)
	if !validToken(token) {
		return "", fmt.Errorf("provide the enrollment token through stdin")
	}
	return token, nil
}

func readCA(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("CA file exceeds 1 MiB")
	}
	return data, err
}

func newEnrollment(server string, certificate []byte, deviceID string) (State, error) {
	token, err := readEnrollmentToken()
	if err != nil {
		return State{}, err
	}
	credential, err := randomCredential()
	if err != nil {
		return State{}, err
	}
	if deviceID == "" {
		deviceID, err = installationID()
		if err != nil {
			return State{}, err
		}
	}
	return State{Server: server, CA: certificate, DeviceID: deviceID, Credential: credential, PendingToken: token}, nil
}

func stopService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for service to stop")
}

func install(args []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	server := flags.String("server", "", "DeployCore HTTPS origin")
	caFile := flags.String("ca", "", "optional CA certificate in PEM format")
	target := flags.String("device-id", "", "device UUID for a recovery token on a new machine")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected installation arguments")
	}
	origin, err := secureOrigin(*server)
	if err != nil {
		return err
	}
	targetID := strings.ToLower(*target)
	if targetID != "" && !deviceIDPattern.MatchString(targetID) {
		return fmt.Errorf("invalid device UUID")
	}
	ca, err := readCA(*caFile)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	existing, err := manager.OpenService(serviceName)
	if err == nil {
		existing.Close()
		return fmt.Errorf("DeployCoreAgent is already installed")
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}

	directory, err := agentDirectory()
	if err != nil {
		return err
	}
	state, err := loadState(directory)
	switch {
	case errors.Is(err, os.ErrNotExist):
		client, checkErr := newClient(origin, ca)
		if checkErr != nil {
			return checkErr
		}
		if checkErr := client.checkReady(context.Background()); checkErr != nil {
			return checkErr
		}
		state, err = newEnrollment(origin, ca, targetID)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	case state.Server != origin || (targetID != "" && targetID != state.DeviceID):
		return fmt.Errorf("saved registration uses a different server or device")
	default:
		if *caFile != "" {
			state.CA = ca
		}
		client, err := newClient(origin, state.CA)
		if err != nil {
			return err
		}
		if err := client.checkReady(context.Background()); err != nil {
			return err
		}
	}
	if err := createPrivateDirectory(directory); err != nil {
		return err
	}

	source, err := os.Executable()
	if err != nil {
		return err
	}
	destination := filepath.Join(directory, exeName)
	if !strings.EqualFold(source, destination) {
		binary, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := atomicWrite(destination, binary); err != nil {
			return err
		}
	}
	if err := saveState(directory, state); err != nil {
		return err
	}
	service, err := manager.CreateService(serviceName, destination, mgr.Config{
		DisplayName: "DeployCore Agent", Description: "Device heartbeat and inventory for DeployCore.",
		StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem",
	}, "service")
	if err != nil {
		return err
	}
	defer service.Close()
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Warning|eventlog.Error); err != nil {
		_ = service.Delete()
		return err
	}
	if err := service.Start(); err != nil {
		_ = eventlog.Remove(serviceName)
		_ = service.Delete()
		return err
	}
	return nil
}

func recoverService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	directory, err := agentDirectory()
	if err != nil {
		return err
	}
	token, err := readEnrollmentToken()
	if err != nil {
		return err
	}
	if err := stopService(service); err != nil {
		return err
	}
	current, err := loadState(directory)
	if err == nil {
		var credential string
		credential, err = randomCredential()
		if err == nil {
			current.Credential = credential
			current.PendingToken = token
			err = saveState(directory, current)
		}
	}
	if err != nil {
		_ = service.Start()
		return err
	}
	return service.Start()
}

func uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	if err := stopService(service); err != nil {
		return err
	}
	if err := service.Delete(); err != nil {
		return err
	}
	return eventlog.Remove(serviceName)
}

func check(args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	server := flags.String("server", "", "DeployCore HTTPS origin")
	caFile := flags.String("ca", "", "optional CA certificate in PEM format")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected check arguments")
	}
	ca, err := readCA(*caFile)
	if err != nil {
		return err
	}
	client, err := newClient(*server, ca)
	if err != nil {
		return err
	}
	if err := client.checkReady(context.Background()); err != nil {
		return err
	}
	fmt.Println("DeployCore HTTPS connection is ready")
	return nil
}

func command(args []string) error {
	if len(args) == 0 {
		return launchSetup()
	}
	switch args[0] {
	case "setup":
		return runSetup()
	case "--help", "-h":
		fmt.Println("deploycore-agent install|check|recover|uninstall|version")
		return nil
	case "version":
		fmt.Println(version)
		return nil
	case "service":
		return svc.Run(serviceName, serviceHandler{})
	case "install":
		return install(args[1:])
	case "recover":
		return recoverService()
	case "uninstall":
		return uninstall()
	case "check":
		return check(args[1:])
	default:
		return fmt.Errorf("unknown command")
	}
}

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if len(os.Args) == 1 || os.Args[1] == "setup" {
			showSetupError(err.Error())
		}
		os.Exit(1)
	}
}
