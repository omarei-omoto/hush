# The README's demo GIF, recorded with VHS (https://github.com/charmbracelet/vhs).
# Re-record with: sh scripts/record-demo.sh   (Docker; uses the Linux binary)

Output assets/demo.gif
Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 760
Set Padding 24
Set Theme "GitHub Dark"
Set TypingSpeed 45ms

Hide
Type "export HUSH_HOME=/tmp/h HUSH_NO_KEYCHAIN=1 HUSH_NO_NUDGE=1 HUSH_NO_DIALOG=1 PS1='$ ' && mkdir -p /tmp/app && cd /tmp/app && hush id --create >/dev/null 2>&1" Enter
Type "printf 'FAL_KEY=fal_live_9d2f81c3a7e4b6f0\nSTRIPE_SECRET_KEY=sk_live_51Hx9QeKZ2mTr8\n' > .env && clear" Enter
Sleep 500ms
Show

Type "cat .env                          # plaintext, readable by anything you run" Enter
Sleep 1.5s
Type "hush init acme --no-agent >/dev/null" Enter
Sleep 2.5s
Type "hush add .env --as Dev --project" Enter
Sleep 2s
Type "rm .env" Enter
Sleep 600ms
Type `grep -A3 '"FAL_KEY"' .hush/vault.json   # what gets committed: ciphertext` Enter
Sleep 2s
Type `hush run -- sh -c 'echo "deploying with FAL_KEY=$FAL_KEY"'` Enter
Sleep 2.5s
Type "hush ls" Enter
Sleep 3s
