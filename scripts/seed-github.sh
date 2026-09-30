#!/bin/sh
# Create hush's labels and seed issues on GitHub, from .github/labels.json and
# .github/seed-issues/*.md. Run by the maintainer, once, before launch:
#
#   gh auth login && sh scripts/seed-github.sh            # --dry-run to only print
#
# Safe to run again: labels are updated in place (--force), and an issue whose
# title already exists (open or closed) is skipped.
set -eu

REPO="${HUSH_REPO:-omarei-omoto/hush}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
here="$(cd "$(dirname "$0")/.." && pwd)"

command -v gh >/dev/null || { echo "needs the GitHub CLI (gh)"; exit 1; }
command -v node >/dev/null || { echo "needs node"; exit 1; }

node -e '
  for (const l of require(process.argv[1])) console.log([l.name, l.color, l.description].join("\t"));
' "$here/.github/labels.json" | while IFS="$(printf '\t')" read -r name color desc; do
  if [ "$DRY" = 1 ]; then echo "label: $name"; continue; fi
  gh label create "$name" --repo "$REPO" --color "$color" --description "$desc" --force >/dev/null
  echo "label: $name"
done

existing="$(gh issue list --repo "$REPO" --state all --limit 500 --json title --jq '.[].title' 2>/dev/null || true)"

for f in "$here"/.github/seed-issues/*.md; do
  title="$(node -e 'const t=require("fs").readFileSync(process.argv[1],"utf8");console.log(JSON.parse(/^title: (.*)$/m.exec(t)[1]))' "$f")"
  labels="$(node -e 'const t=require("fs").readFileSync(process.argv[1],"utf8");console.log(JSON.parse(/^labels: (.*)$/m.exec(t)[1]).join(","))' "$f")"
  if printf '%s\n' "$existing" | grep -Fxq "$title"; then echo "exists: $title"; continue; fi
  body="$(node -e 'const t=require("fs").readFileSync(process.argv[1],"utf8");process.stdout.write(t.replace(/^---\n[\s\S]*?\n---\n\n/,""))' "$f")"
  if [ "$DRY" = 1 ]; then echo "issue: $title [$labels]"; continue; fi
  gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$body" >/dev/null
  echo "issue: $title"
done
