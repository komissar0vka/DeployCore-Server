$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form = [Windows.Forms.Form]::new()
$form.Text = 'Настройка DeployCore Agent'
$form.ClientSize = [Drawing.Size]::new(620, 488)
$form.MinimumSize = [Drawing.Size]::new(400, 320)
$form.StartPosition = 'CenterScreen'
$form.AutoScroll = $true

function Add-Input([string]$caption, [string]$name, [int]$top) {
    $label = [Windows.Forms.Label]::new()
    $label.Text = $caption
    $label.SetBounds(16, $top, 370, 22)
    $form.Controls.Add($label)

    $field = [Windows.Forms.TextBox]::new()
    $field.Name = $name
    $field.AccessibleName = $caption
    $field.SetBounds(16, ($top + 23), 588, 25)
    $field.Anchor = 'Top, Left, Right'
    $form.Controls.Add($field)
    return $field
}

$server = Add-Input 'HTTPS-адрес сервера (с портом при необходимости)' 'server' 14
$token = Add-Input 'Токен регистрации (для нового компьютера)' 'token' 67
$token.UseSystemPasswordChar = $true
$ca = Add-Input 'Доверенный сертификат PEM (при необходимости)' 'certificate' 120
$form.Add_Shown({ [void]$server.Focus() })

$agreement = [Windows.Forms.TextBox]::new()
$agreement.Name = 'agreement'
$agreement.AccessibleName = 'Соглашение об установке DeployCore Agent'
$agreement.Multiline = $true
$agreement.ReadOnly = $true
$agreement.ScrollBars = 'Vertical'
$agreement.Anchor = 'Top, Left, Right'
$agreement.SetBounds(16, 180, 588, 150)
$agreement.Text = @'
Соглашение об установке DeployCore Agent

Агент устанавливается как служба Windows и запускается автоматически с системными правами. Он передаёт на выбранный HTTPS-сервер имя компьютера, домен или рабочую группу, сетевые адреса, версию ОС и агента, сведения об оборудовании и список установленных программ. Эти данные используются для учёта компьютеров, контроля доступности и диагностики.

Администраторы выбранного сервера могут просматривать эти сведения. Прекратить дальнейшую передачу можно, удалив службу. Ранее переданные сведения остаются на сервере и управляются его администратором.

Подтверждая установку, я соглашаюсь с описанной обработкой и подтверждаю, что уполномочен подключить этот компьютер к указанному серверу.
'@
$form.Controls.Add($agreement)

$accept = [Windows.Forms.CheckBox]::new()
$accept.Name = 'acceptAgreement'
$accept.Text = 'Я принимаю соглашение об установке'
$accept.AutoSize = $true
$accept.Location = [Drawing.Point]::new(16, 340)
$form.Controls.Add($accept)

$status = [Windows.Forms.Label]::new()
$status.Anchor = 'Top, Left, Right'
$status.SetBounds(16, 410, 588, 68)
$form.Controls.Add($status)

function Test-ServerAddress {
    $address = $null
    return ([Uri]::TryCreate($server.Text.Trim(), [UriKind]::Absolute, [ref]$address) -and
        $address.Scheme -eq 'https' -and $address.Host -and $address.AbsolutePath -eq '/' -and
        -not ($address.UserInfo -or $address.Query -or $address.Fragment))
}

function Update-Buttons {
    $valid = Test-ServerAddress
    $check.Enabled = $valid
    $install.Enabled = $valid -and $accept.Checked
}

function Invoke-Agent([bool]$configureService) {
    if (-not (Test-ServerAddress) -or ($configureService -and -not $accept.Checked)) { return }
    $check.Enabled = $false
    $install.Enabled = $false
    $form.UseWaitCursor = $true
    $status.Text = 'Проверяется HTTPS и готовность сервера…'
    $form.Refresh()
    try {
        $origin = $server.Text.Trim()
        $cert = $ca.Text.Trim()
        if (($origin + $cert) -match '["\x00-\x1f]') {
            throw 'Уберите кавычки и управляющие символы из адреса или пути к сертификату.'
        }
        $verb = if ($configureService) { 'install' } else { 'check' }
        $arguments = @($verb, '--server', $origin)
        if ($cert) { $arguments += @('--ca', $cert) }
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            if ($configureService) {
                $secret = $token.Text.Trim()
                if ($secret -and $secret -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'Проверьте токен регистрации.' }
                $output = $secret | & $env:DEPLOYCORE_SETUP_EXE @arguments 2>&1
            } else {
                $output = & $env:DEPLOYCORE_SETUP_EXE @arguments 2>&1
            }
            if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') }
        } finally {
            $ErrorActionPreference = $previousPreference
        }
        $status.Text = if ($configureService) {
            $token.Clear()
            'Служба запущена. Проверьте регистрацию в разделе «Компьютеры».'
        } else { 'Сертификат проверен. Сервер DeployCore доступен.' }
    } catch {
        $status.Text = $_.Exception.Message
    } finally {
        $secret = $null
        $form.UseWaitCursor = $false
        Update-Buttons
    }
}

$check = [Windows.Forms.Button]::new()
$check.Text = 'Проверить HTTPS'
$check.SetBounds(16, 370, 150, 30)
$check.Add_Click({ Invoke-Agent $false })
$form.Controls.Add($check)
$install = [Windows.Forms.Button]::new()
$install.Text = 'Установить службу'
$install.SetBounds(176, 370, 165, 30)
$install.Add_Click({ Invoke-Agent $true })
$form.Controls.Add($install)
$server.Add_TextChanged({ Update-Buttons })
$accept.Add_CheckedChanged({ Update-Buttons })
Update-Buttons
[void]$form.ShowDialog()
