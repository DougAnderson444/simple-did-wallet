import didWallet from '../index.js'

import fixtures from './__fixtures__'

describe('extractByTags', () => {
  it('throws when locked', () => {
    expect.assertions(1)
    try {
      const wallet = didWallet.create(fixtures.exported_wallet_1)
      let extracted = wallet.extractByTags(['B'])
    } catch (e) {
      expect(e.message).toBe(
        'Cannot extractByTags from a ciphered wallet. You must unlock first.'
      )
    }
  })

  it('can lock and unlock', () => {
    const wallet = didWallet.create(fixtures.exported_wallet_1)
    wallet.unlock('abc')

    expect(wallet.ciphered).toBeUndefined()
    expect(wallet.keys).toBeDefined()

    let A = wallet.extractByTags(['A'])
    let B = wallet.extractByTags(['B'])

    let wallet2 = didWallet.create({
      keys: [...A, ...B]
    })

    expect(wallet2.keys).toEqual(wallet.keys)
  })
})
