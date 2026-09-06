import { expect, test, type Page } from '@playwright/test'

/**
 * The faucet page is multi-chain: its network picker writes the bridge store's
 * `depositChain` (shared with BridgePage), and every L1 value on the page —
 * heading, gas symbol, switch target — is derived from the selected chain
 * rather than the build-time VITE_NETWORK. These cases pin that down for all
 * three active networks, because a regression to single-chain would still look
 * correct on Sepolia (the default) and only break on the other two.
 */

type WalletRequest = { method: string; params?: unknown }

/**
 * Install a MetaMask-shaped injected provider that records every request and
 * honours wallet_switchEthereumChain. `startChainId` deliberately differs from
 * the chain each case switches TO — otherwise the page's already-on-chain
 * preflight short-circuits and no switch is ever requested.
 */
async function installMockWallet(page: Page, startChainId: string): Promise<void> {
  await page.addInitScript((initialChainId: string) => {
    let chainId = initialChainId
    const requests: Array<{ method: string; params?: unknown }> = []
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>()
    const provider = {
      isMetaMask: true,
      request: async ({ method, params }: { method: string; params?: unknown }) => {
        requests.push({ method, params })
        if (method === 'eth_chainId') return chainId
        if (method === 'eth_accounts' || method === 'eth_requestAccounts') return []
        if (method === 'wallet_getPermissions') return []
        if (method === 'wallet_switchEthereumChain') {
          const requested = (params as Array<{ chainId?: string }> | undefined)?.[0]?.chainId
          if (requested) chainId = requested
          return null
        }
        return null
      },
      on: (event: string, listener: (...args: unknown[]) => void) => {
        const eventListeners = listeners.get(event) ?? new Set()
        eventListeners.add(listener)
        listeners.set(event, eventListeners)
      },
      removeListener: (event: string, listener: (...args: unknown[]) => void) => {
        listeners.get(event)?.delete(listener)
      },
    }

    Object.defineProperty(window, 'ethereum', {
      configurable: true,
      value: provider,
    })
    Object.defineProperty(window, '__psyWalletRequests', {
      configurable: true,
      value: requests,
    })
  }, startChainId)
}

async function switchRequests(page: Page): Promise<WalletRequest[]> {
  return page.evaluate(() => {
    const requests = (window as unknown as {
      __psyWalletRequests?: Array<{ method: string; params?: unknown }>
    }).__psyWalletRequests ?? []
    return requests.filter((request) => request.method === 'wallet_switchEthereumChain')
  })
}

const CASES = [
  // Sepolia is the default selection, so this case also covers the picker
  // being absent from the interaction entirely.
  { network: 'Sepolia', chainIdHex: '0xaa36a7', startChainId: '0x61', select: false },
  { network: 'BSC Testnet', chainIdHex: '0x61', startChainId: '0xaa36a7', select: true },
  { network: 'Base Sepolia', chainIdHex: '0x14a34', startChainId: '0xaa36a7', select: true },
] as const

for (const { network, chainIdHex, startChainId, select } of CASES) {
  test(`published faucet requests ${network} when switching an injected wallet`, async ({ page }) => {
    await installMockWallet(page, startChainId)

    const response = await page.goto('/faucet', { waitUntil: 'domcontentloaded' })
    expect(response?.ok()).toBeTruthy()

    if (select) {
      await page.getByLabel('Network').selectOption({ label: network })
    }

    await expect(page.getByRole('heading', { name: new RegExp(`Get test .* on ${network}`, 'i') })).toBeVisible()
    await page.getByRole('button', { name: `Switch to ${network}`, exact: true }).click()

    expect(await switchRequests(page)).toEqual([
      { method: 'wallet_switchEthereumChain', params: [{ chainId: chainIdHex }] },
    ])
  })
}
