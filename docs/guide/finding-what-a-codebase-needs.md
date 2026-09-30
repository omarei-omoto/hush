# Finding what a codebase needs

`hush scan` reads your source — `process.env.X`, `os.environ["X"]`,
`os.Getenv("X")`, `std::env::var("X")`, `.env.example`, and a dozen more across
JS/TS, Python, Go, Rust, Ruby, Java, PHP, C# — and reconciles it against the
vault:

```
$ hush scan

  ✓ 12 satisfied by the vault
  ✗ 1 missing

Missing:
  SENDGRID_API_KEY  src/mail.ts, src/jobs/digest.ts

  add them:  hush add SENDGRID_API_KEY
```

Nobody has to maintain a manifest. The code is the manifest.
