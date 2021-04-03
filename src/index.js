import DIDWallet from './DIDWallet.js'

const create = data => {
  return new DIDWallet(data)
}

export default {
  create
}
