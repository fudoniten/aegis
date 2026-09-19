# TODO

Known gaps in Aegis. Host secrets and user secrets both work; what is left is
listed below.

## User secrets: remaining work

The decryption path is built and tested (`tests/user-secrets.nix`). Two things
are outside this repo and have to happen before any secret actually flows.

### 1. Register the user in aegis-secrets (admin, one-off)

Nothing is set up: `aegis-secrets` has no `src/users/*.toml` and no
`keys/users/`. Until someone with the admin key runs

```bash
aegis user add niten --hosts='*' --repo-url git@github.com:fudoniten/aegis-secrets-niten
aegis build user-secrets
```

every host's user-secrets unit finds no manifest, logs that, and succeeds. That
is deliberate -- listing a user before they exist is a no-op, not a failure --
but it does mean the wiring cannot be confirmed end to end from a checkout.

`--hosts='*'` grants every active host now and in future. Narrow it if these
secrets should not be on, say, the mail container.

### 2. `aegis-user add-file` has no `--target`

`manifest.py`'s `SecretEntry` carries `target` and `mode`, and the module
honours `target` when the manifest sets it (covered by the test). Nothing
populates it: `build user-secrets` calls `manifest.add_or_update` with name and
type only, and `aegis-user add-file` has no flag to supply one.

This is now *optional* rather than blocking, because `aegis.userSecrets.files`
in Home Manager places files from `/run/aegis/users/<user>/files/` instead, and
that is the better place for it: the user's own configuration knows where a
file belongs, and a root unit writing into a home directory it does not own is
how the ownership problems in the README start.

Worth doing only for a file that must exist before any user session does -- a
credential a system service reads out of a user's directory. If that case turns
up, add `--target`/`--mode` to `add-file`, store them beside the ciphertext in
the user's repo, and pass them through `build user-secrets`.

### 3. `aegis check` should verify decryptability

`_check_users` in aegis-tools-system flags a user with no private key, and one
whose files are deployed to a host outside their host list. It does not check
that a host can actually decrypt what sits in its own directory -- which is the
check that would have caught the key mismatch years earlier. Add it: for each
`deploy/hosts/<h>/users/<u>/manifest.age`, confirm the host's public key is
among its recipients.

## Smaller items

- `secretsRepoPath` falls back to `build/hosts/` for repositories that predate
  the `deploy/` rename. aegis-secrets migrated some time ago. Drop the fallback
  once no consumer pins an older revision -- it is one of two places that can
  silently disagree about where secrets live.
- `aegis build bundles` is a stub that prints "Not yet implemented"
  (aegis-tools-system). Either implement or remove it; it is reachable from the
  CLI today.
- PLAN.md §4 describes the two-layer user key design that was dropped. The
  banner says so, but the section itself could go once nobody needs the
  rationale.
