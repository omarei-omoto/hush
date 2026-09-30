# Credentials that are a file

Some tools do not read a secret from the environment at all. They read a
*path*: `GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`, a `.p12` keystore, a
client certificate. `hush export` is the wrong answer to that — it writes every
value in the vault to disk and leaves it there.

`--materialize` writes the one file that was asked for, hands the child the
path, and removes it afterwards:

```bash
hush run --materialize GOOGLE_APPLICATION_CREDENTIALS -- node app.js
hush run --materialize KUBECONFIG=/tmp/kube.config -- kubectl get pods
```

With no `=` hush chooses a private path (a `0700` directory, removed with the
file). With a path, that path is used exactly. Either way the file is `0600`,
created with `wx` so an existing file or a planted symlink is a refusal rather
than a write through it, and removed even when the command fails. The value
stays masked in the child's output: reading the file back does not print it.

Because this writes plaintext somewhere the caller chose, it is gated on
**`reveal`**, not on `run` — it is the same class of act as `hush get`. There is
no MCP tool for it, and there never will be: an agent that can materialise a
value to a path and read that path has read the value.
