/**
 * `hush age` — the bridge to hardware keys through age plugins.
 */
import { hushHome } from "../identity.ts";
import { ageAvailable, ageVersion, ageBinary, ageIdentityPath, identityPlugin, recipientsForIdentity } from "../age.ts";
import { type Args } from "../cli/args.ts";
import { bold, cyan, dim, green, info, red, warn } from "../cli/output.ts";

/**
 * `hush age` — status of the age bridge, which is how hardware keys get in.
 * hush never talks to a YubiKey or the Secure Enclave itself; it hands the data
 * key to `age`, and age drives whichever plugin owns that recipient.
 */
export async function cmdAge(_a: Args): Promise<void> {
  const has = ageAvailable();
  info(bold("age bridge"));
  info("");
  info(`  ${has ? green("\u2713") : red("\u2717")} age  ${dim(has ? ageVersion() + "  (" + ageBinary() + ")" : "not installed")}`);
  if (!has) {
    info("");
    info("  Install it to use a YubiKey, the Secure Enclave, or a TPM:");
    info("    " + cyan("brew install age"));
    info(dim("    then a plugin, e.g.  brew install age-plugin-yubikey"));
    return;
  }

  const path = ageIdentityPath();
  info("  " + (path ? green("\u2713") : dim("\u00b7")) + " identity  " + dim(path ?? "none found"));
  if (!path) {
    info("");
    info("  Point hush at one of these, or set HUSH_AGE_IDENTITY:");
    info(dim("    " + hushHome() + "/age-identity.txt"));
    info(dim("    ~/.config/age/keys.txt"));
    info("");
    info("  Software key:   " + cyan("age-keygen -o ~/.hush/age-identity.txt"));
    info("  YubiKey:        " + cyan("age-plugin-yubikey") + dim("  (writes a plugin identity)"));
    info("  Secure Enclave: " + cyan("age-plugin-se keygen -o ~/.hush/age-identity.txt"));
    return;
  }

  const plugin = identityPlugin(path);
  info("  " + (plugin ? green("\u2713") : dim("\u00b7")) + " backend   " +
    dim(plugin ? "age-plugin-" + plugin + " (hardware)" : "software key file"));

  const recipients = recipientsForIdentity(path);
  if (!recipients.length) {
    warn("Could not read a recipient from that identity — is the plugin installed?");
    return;
  }
  info("");
  info("  Your age recipient — hand this to whoever runs the vault:");
  for (const r of recipients) info("    " + cyan(r));
  info("");
  info(dim("    hush team add <you> " + recipients[0].slice(0, 24) + "\u2026"));
  if (plugin) {
    info("");
    info(dim("  Unwrapping the vault key prompts on the hardware, every time."));
  }
}
