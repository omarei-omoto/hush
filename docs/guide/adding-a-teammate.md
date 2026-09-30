# Adding a teammate

They run `hush id --create` and send you one line — their encryption key and
their signing key, together:

```
hush_pk_1xMUlHhmUKj0O_oRPgusa3rYileLjwFcLdSLS2H8KhYog_51Vx0R5kOew0GsoADAILwdX8Jg_0XhoB2wa2vMZY
```

You run:

```bash
hush team add sam hush_pk_1xMU…      # --role admin to let them manage the team too
git commit -am "add sam"
```

That is onboarding. They `git pull` and `hush run` works. No account, no invite,
no server, nothing pasted into chat.

**Signed vaults.** A vault made with `hush init` is signed (hush/v3): its header
— who can read it, and a commitment to every data key — carries an admin's
signature, and every member's hush checks it before decrypting anything. Only an
admin can change who can read the vault; members can still add and change
values. An older vault is signed the first time an admin changes its membership,
or with `hush team sign`. To make sure the key a vault lists for someone is
really theirs, compare safety numbers over a call:

```bash
hush team verify sam      # sixty digits; sam runs `hush team verify <you>` and reads theirs
```
