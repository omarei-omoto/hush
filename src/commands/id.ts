/**
 * `hush id` — show or create this machine's key.
 *
 * What it prints is the one string a teammate hands an admin: the encryption
 * key and, since 1.0, the signing key together (`hush_pk_` + 64 bytes). An
 * older 32-byte `hush_pk_` still works for joining a vault; it just cannot be
 * made an admin who signs. An identity that is only an age recipient (a
 * hardware key) prints the recipient, and its signing key on a second line
 * once it has one.
 *
 * `hush id --enclave` makes a key in this Mac's Secure Enclave (enclave.ts):
 * it cannot be copied off the machine, and every use asks for a fingerprint.
 * It does not replace the software key — an admin adds it as a second member
 * (`hush secure --hardware` does that for your own vaults), and then the
 * software key can be retired.
 */
import { loadIdentity, createIdentity, signerFor, type ResolvedIdentity } from "../identity.ts";
import { encodeSpk, encodeSePub } from "../crypto.ts";
import { createEnclaveIdentity, enclaveAvailable, loadEnclaveIdentity } from "../enclave.ts";
import { memberKeyString } from "../vault.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, out } from "../cli/output.ts";

function show(id: ResolvedIdentity, heading: string): void {
  info(bold(heading));
  info(cyan(memberKeyString(id)));
  if (!id.pub) {
    const signer = signerFor(id);
    if (signer) info(cyan(encodeSpk(signer.spk)) + dim("   (signing key: an admin adds it with --spk)"));
  }
  // A software key and an enclave key side by side, mid-upgrade: show both.
  if (id.pub && id.se) {
    info("");
    info(bold("Your Secure Enclave key:"));
    info(cyan(encodeSePub(id.se.pub)));
    const signer = signerFor({ se: id.se });
    if (signer) info(cyan(encodeSpk(signer.spk)) + dim("   (its signing key: an admin adds it with --spk)"));
  }
}

function enclave(a: Args): void {
  const presence = str(a, "presence", "touch");
  if (presence !== "touch" && presence !== "none") die(`--presence is "touch" or "none", not "${presence}"`);
  const existing = loadEnclaveIdentity();
  if (existing && !bool(a, "force")) {
    info(`${dim("This Mac already has an enclave key (--force makes a new one; the old one stops working).")}`);
  } else {
    const ready = enclaveAvailable();
    if (!ready.ok) die(`No Secure Enclave key: ${ready.reason}.`, "A YubiKey through age works anywhere: see docs/BIOMETRY.md.");
    createEnclaveIdentity(presence);
    info(`${green("✓")} a key was made inside this Mac's Secure Enclave`);
    info(
      dim(
        presence === "touch"
          ? "  It cannot leave this Mac, and every use asks for your fingerprint (or the Mac's password)."
          : "  It cannot leave this Mac. --presence none: it is used without asking — for a build machine, not a laptop.",
      ),
    );
  }
  const se = loadEnclaveIdentity()!;
  const signer = signerFor({ se }, true)!;
  info("");
  info(bold("Your enclave key — an admin adds it as a member:"));
  info(cyan(encodeSePub(se.pub)));
  info(cyan(encodeSpk(signer.spk)) + dim("   (its signing key, for --role admin: --spk)"));
  info("");
  info(dim(`On your own vaults, ${"`hush secure --hardware`"} adds it for you.`));
}

export async function cmdId(a: Args): Promise<void> {
  if (bool(a, "enclave")) return enclave(a);
  if (bool(a, "create")) {
    const id = createIdentity("default", bool(a, "force"));
    info(`${green("✓")} identity created  ${dim(`(stored in ${id.source})`)}`);
    info("");
    show(id, "Your public key — send this to whoever runs the vault:");
    return;
  }
  const id = loadIdentity();
  if (!id) die("No identity on this machine.", "Run `hush id --create`.");
  if (bool(a, "quiet")) return out(memberKeyString(id));
  show(id, "Your public key:");
  info(dim(`stored in: ${id.source}`));
}
