import didWallet from '../index.js'
import fixtures from './__fixtures__'

describe('mnemonic', () => {
  it('can add mnemonic', () => {
    const wallet = didWallet.create()
    wallet.addKey({
      type: 'mnemonic',
      encoding: 'bip39',
      mnemonic: fixtures.bip39_mnemonic_0,
      tags: ['did:example:456', 'A'],
      notes: ''
    })
    const A = wallet.extractByTags(['A'])
    expect(A[0].mnemonic).toBe(fixtures.bip39_mnemonic_0)
  })
})
