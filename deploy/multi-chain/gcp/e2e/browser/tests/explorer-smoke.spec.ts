import { expect, test } from '@playwright/test'

const explorerUrl = process.env.EXPLORER_URL ?? 'https://explorer-stg.psy-protocol.xyz'

test('published explorer renders its live shell', async ({ page }, testInfo) => {
  const response = await page.goto(explorerUrl, { waitUntil: 'domcontentloaded' })
  expect(response?.ok()).toBeTruthy()
  await expect(page.locator('#root')).not.toBeEmpty()
  await expect(page.locator('body')).not.toContainText('Bridge configuration error')
  await expect(page.locator('body')).not.toContainText('Application error')

  await testInfo.attach('explorer-smoke-evidence.json', {
    body: Buffer.from(JSON.stringify({
      url: page.url(),
      title: await page.title(),
      rootTextLength: (await page.locator('#root').innerText()).length,
    }, null, 2)),
    contentType: 'application/json',
  })
})
