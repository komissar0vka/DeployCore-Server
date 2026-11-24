const assert = require('node:assert/strict')
const { mkdirSync, readFileSync } = require('node:fs')
const { join } = require('node:path')
const { chromium } = require('playwright')

const credentials = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const target = process.argv[3]
mkdirSync(target, { recursive: true })

const pages = {
  dashboard: 'Дашборд', devices: 'Устройства', software: 'Программы', agent: 'Установка агента',
  agents: 'Агенты Windows', jobs: 'Задания', inventory: 'Инвентаризация', users: 'Пользователи',
  audit: 'Журнал событий', settings: 'Настройки', licenses: 'Лицензия',
}

async function run() {
  const browser = await chromium.launch()
  try {
    const page = await browser.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1366, height: 768 } })
    await page.goto(credentials.origin)
    await page.getByLabel('Имя пользователя').fill(credentials.username)
    await page.getByLabel('Пароль', { exact: true }).fill(credentials.password)
    await page.getByRole('button', { name: 'Войти', exact: true }).click()
    const sidebar = page.getByRole('navigation', { name: 'Разделы панели' })
    await sidebar.waitFor()
    for (const theme of ['dark', 'light']) {
      await page.setViewportSize(theme === 'dark' ? { width: 1366, height: 768 } : { width: 1920, height: 1080 })
      await page.evaluate(value => {
        document.documentElement.dataset.theme = value
        localStorage.setItem('deploycore-theme', value)
      }, theme)
      for (const [key, label] of Object.entries(pages)) {
        await sidebar.getByRole('button', { name: label, exact: true }).click()
        await page.getByRole('heading', { name: label, exact: true }).first().waitFor()
        if (key === 'settings') {
          await page.getByRole('button', { name: 'Создать копию', exact: true }).waitFor()
          await page.getByRole('link', { name: 'Скачать', exact: true }).first().waitFor()
          await page.getByRole('button', { name: 'Показать журнал', exact: true }).click()
          await page.getByText('Server запущен', { exact: true }).waitFor()
        }
        await page.locator('.animate-pulse').first().waitFor({ state: 'hidden', timeout: 5000 }).catch(() => {})
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `${theme} ${key} overflow`)
        await page.screenshot({ path: join(target, `${theme}-${key}.png`), animations: 'disabled', fullPage: true })
      }
    }
    console.log('22 hosted Chromium screenshots captured')
  } finally {
    await browser.close()
  }
}

run().catch(error => { console.error(error); process.exitCode = 1 })
