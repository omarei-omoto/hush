// hush-enclave — a hush identity whose private key lives in the Secure Enclave.
//
// The key is a P-256 key agreement key made *inside* the enclave. What leaves
// it is `dataRepresentation`: a blob sealed by this Mac's enclave, useless to
// anyone else and on any other machine. hush keeps the blob in
// ~/.hush/enclave-identity; the private key itself never exists outside the
// enclave, not even for this program.
//
// No Developer ID, no entitlements: CryptoKit's enclave keys are not keychain
// items, so this works from the ad-hoc-signed binary hush compiles for itself
// (src/swift.ts) — verified on Apple silicon, macOS 26.
//
//   hush-enclave available              exit 0 if there is an enclave, 2 if not
//   hush-enclave create touch|none      print {"blob":…,"pub":…} (base64)
//   hush-enclave pub <blobfile>         print the public key (base64, X9.63)
//   hush-enclave ecdh <blobfile> <why>  read a peer public key (base64) on stdin,
//                                       print the shared secret (base64)
//
// With `touch`, every ecdh asks for a fingerprint (or the Mac's password as
// the system fallback), enforced by the enclave itself — not by this program
// and not by hush. Exit codes: 0 ok, 2 unavailable, 1 anything else.

import CryptoKit
import Foundation
import LocalAuthentication

func fail(_ message: String, _ code: Int32 = 1) -> Never {
  FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
  exit(code)
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: hush-enclave available|create|pub|ecdh") }
guard SecureEnclave.isAvailable else { fail("no Secure Enclave on this Mac", 2) }

func loadKey(_ path: String, context: LAContext? = nil) -> SecureEnclave.P256.KeyAgreement.PrivateKey {
  guard let text = try? String(contentsOfFile: path, encoding: .utf8),
        let blob = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
  else { fail("could not read the enclave key blob") }
  do {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
  } catch {
    fail("this enclave key cannot be opened here: \(error.localizedDescription)")
  }
}

switch args[1] {
case "available":
  exit(0)

case "create":
  let presence = args.count >= 3 ? args[2] : "touch"
  var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
  if presence == "touch" { flags.insert(.userPresence) }
  var error: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
  else { fail("could not describe the key's access: \(String(describing: error))") }
  do {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    let blob = key.dataRepresentation.base64EncodedString()
    let pub = key.publicKey.x963Representation.base64EncodedString()
    print("{\"blob\":\"\(blob)\",\"pub\":\"\(pub)\"}")
  } catch {
    fail("the enclave could not make a key: \(error.localizedDescription)")
  }

case "pub":
  guard args.count >= 3 else { fail("usage: hush-enclave pub <blobfile>") }
  print(loadKey(args[2]).publicKey.x963Representation.base64EncodedString())

case "ecdh":
  guard args.count >= 3 else { fail("usage: hush-enclave ecdh <blobfile> <reason>") }
  let context = LAContext()
  context.localizedReason = args.count >= 4 ? args[3] : "use your hush key"
  let key = loadKey(args[2], context: context)
  let input = FileHandle.standardInput.readDataToEndOfFile()
  guard let text = String(data: input, encoding: .utf8),
        let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
  else { fail("expected a base64 public key on stdin") }
  do {
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: raw)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    print(shared.withUnsafeBytes { Data($0) }.base64EncodedString())
  } catch {
    fail("the enclave did not agree a key: \(error.localizedDescription)")
  }

default:
  fail("unknown command \(args[1])")
}
