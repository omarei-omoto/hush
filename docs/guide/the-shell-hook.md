# The shell hook

`hush hook zsh` (or `bash` / `fish` / `powershell` / `nu`) prints a directory
hook that loads secrets on `cd` and **unsets them again when you leave**. Without that unload you carry
production credentials into every unrelated process you start afterwards, which
is worse than not using hush at all.

For Nushell, add the output of `hush hook nu` to your `config.nu`; it registers a PWD
environment-change hook.

It is still the least safe way to use hush: anything launched from that shell —
your coding agent included — inherits the secrets. `hush run` is the safe form,
and the hook prints that warning every time.
