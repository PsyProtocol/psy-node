import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

type RuntimeChain = {
  name: string
  network: string
  chain_id: number
  chain_index: number
  rpc_url: string
  public_rpc_domain: string
  contracts: { Bridge: string }
  protocol: { chain: { name: string } }
}

type RuntimeConfig = { chains: RuntimeChain[] } | RuntimeChain[]

const runtimePath = resolve(
  process.env.MULTICHAIN_RUNTIME_FILE ?? '../../runtime/l1-deployments.json',
)
const runtime = JSON.parse(readFileSync(runtimePath, 'utf8')) as RuntimeConfig
const chains = Array.isArray(runtime) ? runtime : runtime.chains
const publicRpcAllowlist = readFileSync(
  resolve(
    process.env.PSY_DAPP_CHAIN_CONFIG_FILE
      ?? '../../../../../psy-dapp/apps/bridge/src/services/chainConfig.ts',
  ),
  'utf8',
)

function assertRuntimeMatrix(): void {
  expect(chains.map((chain) => chain.network)).toEqual([
    'sepolia',
    'bscTestnet',
    'baseSepolia',
  ])
  expect(chains.map((chain) => chain.chain_index)).toEqual([0, 1, 2])
}

async function collectPublishedModules(
  page: Page,
  request: APIRequestContext,
): Promise<string> {
  const initialUrls = await page.locator('script[src], link[rel="modulepreload"][href]').evaluateAll(
    (elements) => elements
      .map((element) => element.getAttribute('src') ?? element.getAttribute('href'))
      .filter((value): value is string => Boolean(value)),
  )
  const origin = new URL(page.url()).origin
  const pending = initialUrls.map((url) => new URL(url, page.url()).href)
  const visited = new Set<string>()
  const sources: string[] = []
  const moduleReference = /["']((?:\.\.?\/|\/)[^"']+\.js(?:\?[^"']*)?)["']/g
  const maxModules = 500
  const fetchConcurrency = 16

  while (pending.length > 0) {
    const batch: string[] = []
    while (pending.length > 0 && batch.length < fetchConcurrency) {
      const url = pending.shift()!
      if (visited.has(url) || new URL(url).origin !== origin) continue
      visited.add(url)
      batch.push(url)
    }
    expect(
      visited.size,
      'published JavaScript module graph is unexpectedly large',
    ).toBeLessThanOrEqual(maxModules)

    const fetched = await Promise.all(batch.map(async (url) => {
      const response = await request.get(url)
      expect(response.ok(), `failed to fetch published module ${new URL(url).pathname}`).toBeTruthy()
      return { url, source: await response.text() }
    }))

    for (const { url, source } of fetched) {
      sources.push(source)
      for (const match of source.matchAll(moduleReference)) {
        const child = new URL(match[1], url).href
        if (!visited.has(child)) pending.push(child)
      }
    }
  }

  expect(sources.length, 'no published JavaScript modules were discovered').toBeGreaterThan(0)
  return sources.join('\n')
}

test('published app contains the complete three-chain deployment', async ({ page, request }) => {
  assertRuntimeMatrix()
  const response = await page.goto('/', { waitUntil: 'domcontentloaded' })
  expect(response?.ok()).toBeTruthy()
  await expect(page.locator('#root')).not.toBeEmpty()
  await expect(page.locator('body')).not.toContainText('Bridge configuration error')

  const publishedSource = await collectPublishedModules(page, request)
  const normalizedSource = publishedSource.toLowerCase()

  for (const chain of chains) {
    expect(
      normalizedSource.includes(chain.contracts.Bridge.toLowerCase()),
      `${chain.network} Bridge is absent from the published app`,
    ).toBe(true)
    expect(
      publishedSource.includes(chain.protocol.chain.name),
      `${chain.network} label is absent from the published app`,
    ).toBe(true)

    const publicRpc = `https://${chain.public_rpc_domain}`
    if (chain.rpc_url !== publicRpc && !publicRpcAllowlist.includes(chain.rpc_url)) {
      expect(
        publishedSource.includes(chain.rpc_url),
        `${chain.network} private upstream RPC leaked into the app`,
      ).toBe(false)
    }
  }
})

test('browser can reach every configured chain and deployed Bridge', async ({ page }) => {
  assertRuntimeMatrix()
  await page.goto('/', { waitUntil: 'domcontentloaded' })

  const results = await page.evaluate(async (matrix) => {
    async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
      const controller = new AbortController()
      const timer = window.setTimeout(() => controller.abort(), 15_000)
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
          signal: controller.signal,
        })
        const body = await response.json() as {
          result?: unknown
          error?: { code?: number; message?: string }
        }
        if (!response.ok || body.error || body.result == null) {
          throw new Error(`HTTP ${response.status}; RPC ${JSON.stringify(body.error ?? null)}`)
        }
        return body.result
      } finally {
        window.clearTimeout(timer)
      }
    }

    const checks = []
    for (const chain of matrix) {
      const url = `https://${chain.public_rpc_domain}`
      try {
        const chainId = await rpc(url, 'eth_chainId', [])
        const bridgeCode = await rpc(url, 'eth_getCode', [chain.contracts.Bridge, 'latest'])
        checks.push({ network: chain.network, ok: true, chainId, bridgeCode })
      } catch (error) {
        checks.push({ network: chain.network, ok: false, error: String(error) })
      }
    }
    return checks
  }, chains)

  for (const chain of chains) {
    const result = results.find((candidate) => candidate.network === chain.network)
    expect(result?.ok, `${chain.network} browser RPC failed: ${result?.error ?? 'missing result'}`)
      .toBeTruthy()
    expect(result?.chainId).toBe(`0x${chain.chain_id.toString(16)}`)
    expect(result?.bridgeCode).toMatch(/^0x[0-9a-f]+$/i)
    expect(result?.bridgeCode).not.toBe('0x')
  }
})
