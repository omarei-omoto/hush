/**
 * `hush id` — show or create this machine's key.
 */
import { loadIdentity, createIdentity, publicKeyOf } from "../identity.ts";
import { type Args, bool } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, out } from "../cli/output.ts";

export async function cmdId(a: Args): Promise<void> {
  if (bool(a, "create")) {
    const id = createIdentity("default", bool(a, "force"));
    info(`${green("✓")} identity created  ${dim(`(stored in ${id.source})`)}`);
    info("");
    info(bold("Your public key — send this to whoever runs the vault:"));
    info(cyan(publicKeyOf(id)));
    return;
  }
  const id = loadIdentity();
  if (!id) die("No identity on this machine.", "Run `hush id --create`.");
  if (bool(a, "quiet")) return out(publicKeyOf(id));
  info(bold("Your public key:"));
  info(cyan(publicKeyOf(id)));
  info(dim(`stored in: ${id.source}`));
}
