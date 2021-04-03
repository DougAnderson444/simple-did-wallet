import { hash } from '@stablelib/sha256'
import { encodeURLSafe } from '@stablelib/base64'

export default (publicKey) => {
  try {
    const jwk = JSON.parse(publicKey)
    if (jwk.kid) {
      return jwk.kid
    }
  } catch (e) {
    // do nothing
  }
  return encodeURLSafe(hash(publicKey))
}
