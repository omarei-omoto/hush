# Running things

```bash
hush npm run dev              # anything after hush that is not a hush command
hush bun dev                  #   runs with this project's sets injected
hush python app.py
hush ./deploy.sh

hush dev                      # find package.json, run its dev script with the
hush dev build                #   package manager the lockfile names (bun/pnpm/yarn/npm)

hush run --use prod -- ./deploy.sh    # the explicit form; --use adds a set for this run
```

Output is redacted: an injected value that shows up in stdout or stderr comes
out as `[redacted:KEY]`. A hush command always wins over a same-named program,
so `hush ls` is hush's `ls`, never `/bin/ls`.
