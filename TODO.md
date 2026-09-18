# TODO

Known gaps in Aegis, with enough detail to act on. Host secrets — SSH host keys,
keytabs, Nexus keys, role secrets, Nebula material — work and are deployed; none
of the below affects them.

## User secrets do not work end to end

Nothing a user puts in their `aegis-secrets-<username>` repo reaches a host
today. There are four separate problems, and the first is the one that decides
the others.

### 1. The two halves disagree about how user secrets are keyed

`modules/secrets.nix` (`userKeyEntries`) generates a phase-1 unit that decrypts

    deploy/hosts/<host>/users/<username>/.key.age  ->  /run/aegis/users/<username>/.key

and a phase-2 unit that uses that key to decrypt the user's manifest and each of
their secrets. This follows PLAN.md §4, "User Keys (Two-Layer System)": a *user
repo key* for user→admin, and a separate *user deployment key* for admin→host.

`aegis-tools-system` only ever built the first layer:

- `aegis user add` writes the user's private key to `keys/users/<username>.age`,
  encrypted **to admins only** (`aegis/cli.py`, `add_user`).
- Nothing anywhere emits `deploy/hosts/<host>/users/<username>/.key.age`.
- `aegis build user-secrets` re-encrypts each secret to `[host_key, *admin_keys]`
  and the manifest to host + admins + user — i.e. everything on the host side is
  keyed to the **host master key**, not to any user key.

So the phase-1 unit fails for want of a file that is never generated, and
because the phase-2 unit `Requires=` it, user secrets never run at all. Had the
file existed, it would have decrypted nothing, because the ciphertext is not
encrypted to it.

**Decide one of:**

- **(a) Drop the deployment-key layer.** Have `userKeyEntries` disappear and the
  phase-2 unit decrypt with `cfg.masterKeyPath`. Matches what the tools already
  produce; no change to `aegis-tools-system`; one less key to rotate. The user
  key then exists only to get secrets from the user's repo into aegis-secrets,
  which is all it was ever actually used for.
- **(b) Build the second layer.** Have `aegis user add` generate a deployment
  keypair, `aegis build user-secrets` write `.key.age` per host (encrypted to
  that host) and encrypt secrets to the deployment public key instead of the
  host key. Costs work in aegis-tools-system, and buys a boundary that is only
  meaningful if something other than root reads these files — which today
  nothing does, since the phase-2 unit runs as root and chowns afterwards.

(a) is the recommendation. It is a deletion in this repo and a no-op in
aegis-tools-system, and the trust boundary (b) protects is not one this design
actually has.

Whichever is chosen, delete the `# TODO(user-secrets)` block in
`modules/secrets.nix` and the stale half of PLAN.md §4 with it.

### 2. File secrets cannot be placed in a home directory

`aegis-tools-system`'s manifest format (`manifest.py`, `SecretEntry`) carries
`target` and `mode` fields, and `modules/secrets.nix` honours `target` when it
is set. Nothing populates them: `build user-secrets` calls
`manifest.add_or_update` with name and type only, and `aegis-user add-file` has
no `--target` flag to supply one.

Every file secret therefore lands at `/run/aegis/users/<username>/files/<name>`,
root-written, mode `0400`, and there is no way to ask for it anywhere else.

Two halves: add `--target`/`--mode` to `aegis-user add-file` (stored beside the
ciphertext in the user's repo) and pass them through `build user-secrets` into
the manifest.

Placement into `$HOME` is arguably not this module's job at all — a root unit
writing into a home directory it does not own is how the ownership problems
documented in the README start. The alternative is to let aegis stop at
`/run/aegis/users/<username>/` and have the Home Manager layer place files from
there. Worth settling before building `--target`.

### 3. No user is configured anywhere

Independent of the above, nothing is set up:

- `aegis-secrets` has no `src/users/*.toml`, no `keys/users/`, and no
  `deploy/hosts/*/users/`. `aegis user add niten` has never been run.
- No host sets `aegis.secrets.users`. `nixos-config/identity/aegis.nix` does not
  set it, and the `secret-users` entries in various `hosts/*/config.nix` are the
  legacy fudo-lib `/secrets` option, unrelated to aegis.

`aegis check` already has `_check_users`, which flags a user with no private key
and files deployed to a host outside their host list. Extend it to fail when a
user's deployed directory cannot actually be decrypted by the host it sits in —
that is the check that would have caught problem 1.

### 4. `aegis.userSecrets` is imported nowhere

The Home Manager module in `modules/home-secrets.nix` is not imported by
`nixos-config` (which takes only `nixosModules`) or by `fudo-nix-home` (which
has no aegis reference at all). Wiring it up is blocked on 1; it exports
variables from a directory nothing fills.

## Smaller items

- `secretsRepoPath` falls back to `build/hosts/` for repositories that predate
  the `deploy/` rename. aegis-secrets migrated some time ago. Drop the fallback
  once no consumer pins an older revision — it is one of two places that can
  silently disagree about where secrets live.
- `aegis build bundles` is a stub that prints "Not yet implemented"
  (aegis-tools-system). Either implement or remove it; it is reachable from the
  CLI today.
