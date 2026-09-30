# What someone removed could still use

`hush team rm sam` re-keys everything Sam could read, so their copy of the repo
opens nothing new. What they already read, they have. Every value they could
read is marked until it is set again:

```bash
hush exposed           # each value, who could read it, and where to replace it (Stripe, OpenAI, AWS, …)
hush ls --age          # every value, oldest first
```

`"rotateAfterDays": 90` in a policy (or `{ "prod": 30, "*": 180 }`) makes
`hush level` and `hush doctor` list values older than that. A floor can ask to
be told sooner than a repository does, never later.
