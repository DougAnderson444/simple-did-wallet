import didWallet from '../index.js'

import fixtures from './__fixtures__'

const keyToKID = require('../keyToKID')

describe('create', () => {
  it('can create empty wallet', () => {
    const wallet = didWallet.create()
    expect(wallet.keys).toEqual({})
  })

  it('throws when assymetric key is not valid', () => {
    expect.assertions(1)
    try {
      const key = {
        type: 'assymetric'
      }
      const wallet = didWallet.create({
        keys: [key]
      })
    } catch (e) {
      expect(e.message).toBe('is not exactly one from </assymetricWalletKey>,</mnemonicWalletKey>')
    }
  })

  it('can create with valid keys', () => {
    const key = {
      type: 'assymetric',
      encoding: 'hex',
      publicKey: fixtures.secp256k1_keypair_0.publicKey,
      privateKey: fixtures.secp256k1_keypair_0.privateKey,
      tags: ['Secp256k1VerificationKey2018', 'did:example:456'],
      notes: ''
    }
    const wallet = didWallet.create({
      keys: [key]
    })
    const kid = keyToKID(fixtures.secp256k1_keypair_0.publicKey)
    expect(wallet.keys[kid]).toEqual({
      ...key,
      kid
    })
  })

  it('can create with many keys', () => {
    const wallet = didWallet.create({
      keys: [
        {
          type: 'assymetric',
          encoding: 'hex',
          publicKey: fixtures.secp256k1_keypair_0.publicKey,
          privateKey: fixtures.secp256k1_keypair_0.privateKey,
          tags: ['Secp256k1VerificationKey2018', 'did:example:456', 'A'],
          notes: ''
        },
        {
          type: 'assymetric',
          encoding: 'hex',
          publicKey: fixtures.secp256k1_keypair_1.publicKey,
          privateKey: fixtures.secp256k1_keypair_1.privateKey,
          tags: ['Secp256k1VerificationKey2018', 'did:example:456', 'A'],
          notes: ''
        },
        {
          type: 'assymetric',
          encoding: 'hex',
          publicKey: fixtures.secp256k1_keypair_2.publicKey,
          privateKey: fixtures.secp256k1_keypair_2.privateKey,
          tags: ['Secp256k1VerificationKey2018', 'did:example:456', 'B'],
          notes: ''
        }
      ]
    })
    wallet.lock('abc')

    expect(wallet.ciphered).toBe(fixtures.exported_wallet_1)
  })
})
