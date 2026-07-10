import Crypto
import Foundation

enum WebAuthnCrypto {
  static func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  static func verifyES256(
    signatureDER: Data,
    signedData: Data,
    publicKeyX963: Data
  ) throws -> Bool {
    let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
    let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
    return publicKey.isValidSignature(signature, for: signedData)
  }

  static func isValidP256PublicKey(x963Representation: Data) -> Bool {
    (try? P256.Signing.PublicKey(x963Representation: x963Representation)) != nil
  }
}
