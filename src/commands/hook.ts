/**
 * `hush hook` (the shell hook) and `hush root`.
 */
import { resolveVaultPath } from "../vault.ts";
import { type Args } from "../cli/args.ts";
import { out, warn } from "../cli/output.ts";

export async function cmdHook(a: Args): Promise<void> {
  const shell = a._[0] || "zsh";
  warn("The shell hook exports secrets into your interactive shell, so every process you");
  warn("launch from it — including your coding agent — inherits them. `hush run` is safer.");
  process.stderr.write("\n");

  if (shell === "powershell" || shell === "pwsh") {
    // Values arrive as JSON and are set one by one: nothing is evaluated as
    // PowerShell, so a value can never run as code. The prompt function runs
    // the hook before each prompt — PowerShell has no cd hook of its own.
    out(`function global:_hush_unload {
  if ($env:HUSH_LOADED_KEYS) {
    foreach ($k in ($env:HUSH_LOADED_KEYS -split ' ')) { if ($k) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue } }
    Remove-Item Env:HUSH_LOADED_KEYS, Env:HUSH_LOADED_DIR -ErrorAction SilentlyContinue
  }
}
function global:_hush_hook {
  $root = (hush root 2>$null)
  if ($root -eq $env:HUSH_LOADED_DIR) { return }
  _hush_unload
  if (-not $root) { return }
  $keys = (hush export --names 2>$null) -join ' '
  $json = (hush export --format json 2>$null | Out-String)
  if (-not $json.Trim()) { return }
  ($json | ConvertFrom-Json).PSObject.Properties | ForEach-Object { Set-Item -Path "Env:$($_.Name)" -Value $_.Value }
  $env:HUSH_LOADED_DIR = $root
  $env:HUSH_LOADED_KEYS = $keys
}
if (-not $global:_hush_prompt) { $global:_hush_prompt = $function:prompt }
function global:prompt { _hush_hook; & $global:_hush_prompt }
_hush_hook`);
    return;
  }

  if (shell === "fish") {
    out(`function _hush_unload
  if set -q HUSH_LOADED_KEYS
    for k in (string split " " -- $HUSH_LOADED_KEYS)
      set -e $k
    end
    set -e HUSH_LOADED_KEYS HUSH_LOADED_DIR
  end
end

function _hush_hook --on-variable PWD
  set -l root (hush root 2>/dev/null)
  if test "$root" = "$HUSH_LOADED_DIR"
    return
  end
  _hush_unload
  test -z "$root"; and return
  set -l keys (hush export --names 2>/dev/null | tr '\\n' ' ')
  hush export --shell 2>/dev/null | source
  or return
  set -gx HUSH_LOADED_DIR $root
  set -gx HUSH_LOADED_KEYS $keys
end`);
    return;
  }

  // The important half is the unload. Without it you keep production
  // credentials in your shell after cd-ing away, and hand them to every
  // unrelated process you start afterwards.
  const SPLIT = shell === "bash" ? "$HUSH_LOADED_KEYS" : "${=HUSH_LOADED_KEYS}";
  out(`_hush_unload() {
  if [ -n "$HUSH_LOADED_KEYS" ]; then
    for k in ${SPLIT}; do unset "$k"; done
    unset HUSH_LOADED_KEYS HUSH_LOADED_DIR
  fi
}
_hush_hook() {
  local root keys
  root="$(hush root 2>/dev/null)"
  [ "$root" = "$HUSH_LOADED_DIR" ] && return 0
  _hush_unload
  [ -z "$root" ] && return 0
  keys="$(hush export --names 2>/dev/null | tr '\\n' ' ')" || return 0
  eval "$(hush export --shell 2>/dev/null)" || return 0
  export HUSH_LOADED_DIR="$root"
  export HUSH_LOADED_KEYS="$keys"
}`);
  out(shell === "bash"
    ? 'PROMPT_COMMAND="_hush_hook;$PROMPT_COMMAND"'
    : "autoload -U add-zsh-hook && add-zsh-hook chpwd _hush_hook");
  out("_hush_hook");
}
export async function cmdRoot(): Promise<void> {
  const loc = resolveVaultPath(process.cwd());
  if (!loc) process.exit(1);
  out(loc.hushDir.replace(/[/\\]\.hush$/, ""));
}
