/**
 * `hush help` and `hush help --all`.
 */
import { VERSION } from "../version.ts";
import { bold, dim } from "../cli/output.ts";

// --------------------------------------------------------------------- help

/**
 * `hush help` — eight lines, chosen after watching people bounce off a 35-command
 * screen with two vocabularies (environments and service accounts) fighting for
 * the same idea. `hush help --all` (below) still lists everything.
 */
export const SHORT_HELP = `${bold("hush")} ${dim(VERSION)}

  hush add <file|KEY=value>   save secrets as a named set
  hush use <set> ...          this project uses these sets
  hush run -- <cmd>           run with them injected
  hush dev                    run your dev script with them
  hush ls                     library, project, what is used
  hush rm <KEY|set>           remove
  hush ui                     the app
  hush team add|rm            share this project's vault

  hush help --all             every command
`;

export const FULL_HELP = `${bold("hush")} ${dim(VERSION)} — envelope-encrypted team secrets your agent can use but never read

${bold("daily")}
  hush start                               never used this? a few questions, and you're set up
  hush add <file>                          save a .env-shaped file as a named set
  hush add KEY=value [KEY=value…]          save one or more values directly
  hush add <service>                       e.g. hush add fal — prompted, hidden input
  hush import <file|-> --as <set>           bring in another tool's export (dotenv, json, 1password)
  hush use <set> [<set>…]                  this project uses these sets, in order (later wins)
  hush use                                 show what this project uses, and where from
  hush use --not <set>                     stop using it here
  hush run [--use <set>…] -- <cmd>         run with them injected, output redacted
  hush run --materialize KEY -- <cmd>      write that secret to a file; the child gets the path
  ${dim("(pass-through: npm run dev, python app.py, … run the same way)")}
  ${dim("(in a folder that isn't set up yet, hush asks which of your sets it should use)")}
  hush dev [script]                        find package.json, run it with them injected
  hush request [METHOD] <url> [--header 'Name: $VAR'] [--data @file]
                                           call an API with a secret injected, response redacted
  hush ls [<set>]                          library, project, what is used — or one set's keys
  hush ls [<set>] --age                    how long since each value was replaced, oldest first
  hush exposed                             values someone removed could still use, and where to replace them
  hush rm <KEY> [--from <set>]             remove a key
  hush rm <set> [--yes]                    remove a whole set
  hush ui                                  open the local app to manage everything
  hush team ls|add|rm                      share this project's vault

${bold("sets")}          — a set you name, describe and reuse
  hush env rename <name> <new name>    re-seals every value under the new name
  hush env describe <name> [--description <t>] [--when <t>]
  hush env describe <name> --only-in "~/code/modio-*"   usable only in those folders (--anywhere undoes it)
  hush env move <KEY>… --to <set>      carve one big pile into named sets
  hush global [<vault>|--create]       which vault holds your library

${bold("sharing")}
  hush team ls
  hush team add <name> <pk>     re-wraps the key for them; commit and they're in
  hush team rm <name>           removes them and re-encrypts everything
  hush team accept|reject       someone else changed who can read the vault — check, then decide
  hush team add <n> <pk> --sets a,b   a member who reads only those sets
  hush team rm <name> --from <set>    take one set away from a scoped member
  hush team sign                sign this vault (admins only change who can read it)
  hush team verify <name>       a safety number to compare over a call
  hush ci create <name> --sets a,b    a CI identity that reads only those sets
  hush id [--create]            show or create this machine's key
  hush id --enclave             make a key in this Mac's Secure Enclave (Touch ID per use)
  hush link <vault> [--env e]   point this repo at a vault you already have
  hush merge-driver --install   merge vault.json key by key in this clone's git merges
  hush merge [status|pick]      finish a git merge that stopped on the vault; choose per key

${bold("hardening")}
  hush level                    where you are on the security ladder
  hush secure                   climb the next rung
  hush secure approval --for 30m  ask before anything uses a key; 30m is how long an "Allow" lasts
  hush biometry [setup|test]    gate approvals behind Touch ID
  hush age                      use a YubiKey / Secure Enclave / TPM via age
  hush approvals pair --relay <url>   no one at this machine? send its approvals to your laptop
  hush approvals accept <code>  (on the laptop) approve for the machine that showed the code
  hush approvals listen         (on the laptop) answer them with a dialog or Touch ID
  hush approvals [ls|rm <name>] what is paired with this machine
  hush relay serve              run a relay (it only ever sees sealed messages)
  hush verify                   check the vault decrypts and has not been rolled back
  hush audit [verify]           what hush did here; verify checks nothing was edited out
  hush rotate                   new vault key, same values

${bold("agents")}
  hush install-mcp              register hush with your coding agent
  hush install-skill            teach the agent the rules (--global for all projects)

${bold("other")}
  hush init [name]               create a vault here (.hush/vault.json — commit it)
  hush doctor                    check this machine's setup
  hush hook <zsh|bash|fish|powershell|nu>  auto-load on cd (least safe; unloads on leave)
  hush export [--out .env]       write plaintext out (last resort)
  hush get <KEY>                 reveal one value (asks first)
  hush scan [dir]                what does this codebase need, and is it in the vault?
  hush scan --agents [--fix]     plaintext keys in your agents' configs; --fix moves them into hush
  hush root                      the project root hush would act on

${bold("flags")}
  --use <set>     an extra set for this run only (repeatable; --env is an alias)
  --materialize   (run) KEY or KEY=/path: write that secret to a file, hand the
                  child the path, remove it afterwards. Needs "reveal", not "run".
  --header        (request) 'Name: value'; put $KEY where the secret goes (repeatable)
  --data          (request) the body, or @file / @- to read one
  --substitute    (request) extra places for $KEY: body, query (headers are always allowed)
  --include       (request) print the status line and response headers too
  --for <30m|1h>  (secure approval) how long the dialog's "Allow" lasts
  --json          machine-readable output where it makes sense

${dim("Deprecated, still work until hush 2.0 — each prints a one-line notice: hush set,")}
${dim("hush accounts, hush env ls / env / env use / env drop / env new, --with a:b, use a=b.")}

${dim("Vault files hold only ciphertext and public keys. Your private key never leaves this machine.")}
`;
