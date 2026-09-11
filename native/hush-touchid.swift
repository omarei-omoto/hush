// Touch ID gate for hush.
//
// Deliberately tiny and deliberately honest about its scope: this proves a
// human with an enrolled fingerprint is physically at the machine right now.
// It does NOT protect the identity key at rest — that needs a Secure Enclave
// key, which needs a real Apple Developer ID to sign (see docs/BIOMETRY.md).
//
// Exit codes:  0 = authenticated, 1 = denied/cancelled, 2 = unavailable.
//
// Build:  swiftc -O hush-touchid.swift -o hush-touchid

import Foundation
import LocalAuthentication

let args = CommandLine.arguments

if args.count > 1 && args[1] == "--check" {
    let ctx = LAContext()
    var err: NSError?
    let can = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    // 1 = Touch ID, 2 = Face ID, 0 = none
    print("\(can ? "yes" : "no") \(ctx.biometryType.rawValue)")
    exit(can ? 0 : 2)
}

let reason = args.count > 1 ? args[1] : "unlock your hush vault"

let ctx = LAContext()
// No password fallback: if biometry fails we want the caller to decide,
// not to silently downgrade to something weaker.
ctx.localizedFallbackTitle = ""

var err: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
    FileHandle.standardError.write(
        "unavailable: \(err?.localizedDescription ?? "no biometry")\n".data(using: .utf8)!)
    exit(2)
}

let sem = DispatchSemaphore(value: 0)
var authorized = false
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, _ in
    authorized = ok
    sem.signal()
}
sem.wait()

exit(authorized ? 0 : 1)
