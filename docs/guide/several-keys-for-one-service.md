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
