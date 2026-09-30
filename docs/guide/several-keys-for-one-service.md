# Several keys for one service

The thing you hit every day: a personal key for a service, another for work,
another for a client. Same variable name, different values. Each is a set:

```bash
hush add fal --as "Personal fal" --library    # hush knows fal needs FAL_KEY; asks, hidden
hush add fal --as "Work fal" --library
hush add fal --as "Client fal" --library
```

Use one per project, or one per run:

```bash
hush use work-fal                             # this project, from now on
hush run --use client-fal -- ./build.sh       # this run only — layered last, so it wins
```

**Unknown service?** Tell it the variables once:

```bash
hush add myapi --as "Staging myapi" --vars MYAPI_KEY,MYAPI_SECRET
```

**From a script or CI**, pipe one line per variable, in the order hush asks:

```bash
printf '%s\n' "$FAL_KEY" | hush add fal --as "CI fal"
printf '%s\n%s\n' "$SID" "$TOKEN" | hush add twilio --as "Main twilio"
```

If nothing arrives on stdin, `hush add` fails rather than reporting success — a
run that stored no credential must not look like one that did.

## Keeping a key to some projects

"Use this fal key for MODIO projects only" can be a rule hush enforces, not
just a note your agent may or may not follow:

```bash
hush env describe "FAL MODIO" --only-in "~/code/modio-*"
```

From then on the set works in any folder matching the pattern, and in every
folder inside one (`~/code/modio-app/packages/api` counts). Anywhere else,
hush refuses it for everyone:

- `hush run --use fal-modio` in another project stops before anything runs,
  and says which folders the set is for. So do `hush get`, `hush export` and
  `hush request`.
- `hush use fal-modio` there is refused, so it cannot be linked in.
- A project that linked it before the rule existed has it skipped, with a
  line saying so, and the rest of the run goes ahead.
- An agent sees `only in: ~/code/modio-*` in `hush_list_sets`, and
  `NOT usable in this project` where that applies. If it asks anyway, it is
  refused the same way.
- `hush ls` and the app show the rule, and a project's first-run picker does
  not offer a set it may not use.

Patterns are full paths: `~` is your home folder, `*` matches within one
folder name, `**` across folders, and `?` one character. Give `--only-in` more
than once for several places. Quote the pattern, or the shell will expand
`*` itself. Matching uses real paths, so a symlink named like a MODIO folder
that points somewhere else does not count. On macOS and Windows, case is
ignored, as the file system ignores it.

```bash
hush env describe "FAL MODIO" --only-in "~/code/modio-*" --only-in "~/clients/modio"
hush env describe "FAL MODIO" --anywhere            # lift the rule
```

The library view in `hush ui` still shows and edits the set wherever you open
it. The rule is about where the key is *used*, not where you manage it.
