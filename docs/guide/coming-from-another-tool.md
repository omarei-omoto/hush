# Coming from another tool

`hush add` reads a `.env`. For everything else there is `hush import`, which
reads what your current tool already exports — no accounts, no API tokens, no
vendor SDK:

```bash
# Doppler
doppler secrets download --format json --no-file | hush import - --as "Prod"

# AWS Secrets Manager (the SecretString envelope is unwrapped for you)
aws secretsmanager get-secret-value --secret-id app/prod --query SecretString \
  --output text | hush import - --as "Prod"

# 1Password
op item get "Stripe" --format json | hush import - --format 1password --as "Work"

# any JSON file, checked before anything is stored
hush import secrets.json --format json --as "Prod" --dry-run
```

`--dry-run` lists the names it would write and stores nothing. Nothing prints a
value, in any mode. `--format` is `dotenv` (the default), `json`, or
`1password`; a field whose value is not a string is skipped and counted rather
than stringified into a variable.
