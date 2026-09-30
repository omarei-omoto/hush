/**
 * `hush id` — show or create this machine's key.
 *
 * What it prints is the one string a teammate hands an admin: the encryption
 * key and, since 1.0, the signing key together (`hush_pk_` + 64 bytes). An
 * older 32-byte `hush_pk_` still works for joining a vault; it just cannot be
 * made an admin who signs. An identity that is only an age recipient (a
 * hardware key) prints the recipient, and its signing key on a second line
 * once it has one.
 */
import { loadIdentity, createIdentity, signerFor, type ResolvedIdentity } from "../identity.ts";
import { encodeSpk } from "../crypto.ts";
import { memberKeyString } from "../vault.ts";
import { type Args, bool } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, out } from "../cli/output.ts";

function show(id: ResolvedIdentity, heading: string): void {
  info(bold(heading));
  info(cyan(memberKeyString(id)));
  if (!id.pub) {
    const signer = signerFor(id);
    if (signer) info(cyan(encodeSpk(signer.spk)) + dim("   (signing key: an admin adds it with --spk)"));
  }
}

export async function cmdId(a: Args): Promise<void> {
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
