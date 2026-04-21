# TODO

## Follow-ups from PR #52 (Keychain credentials)

The Keychain credentials PR shipped the core trait + subcommand + migrate
flow, but reviewers surfaced several improvements that are out of scope
for that PR. They are tracked here so they do not get lost.

### Security

- [ ] **Drop `MDE_*` keys loaded from `.env`** before resolution
      (`src/main.rs:16` `dotenvy::dotenv()`). A malicious `.env` in cwd
      can override the user's Keychain secret with attacker-controlled
      credentials, redirecting OAuth flows to the attacker's tenant.
      Either gate dotenv behind an explicit flag, or scrub `MDE_*` keys
      that came from `.env` after loading. Reviewer flagged as High.

- [ ] **Use `tempfile::NamedTempFile::new_in`** for the atomic_replace
      tempfile instead of a unix-nanos suffix
      (`src/commands/credentials.rs` `atomic_replace`). The current name
      is predictable; `create_new` + `O_EXCL` already blocks the symlink
      attack but switching to `tempfile` removes a class of bugs and
      cleans up better on drop. Reviewer flagged as Medium.

- [ ] **Zeroize secret-bearing strings on drop** in the `credentials`
      subcommand path (`src/commands/credentials.rs`). The plaintext
      sits in unzeroed `String`s through `set_value` / `migrate`.
      Reviewer flagged as Low. Likely needs `secrecy::Secret<String>`
      and a sweep of where the secret is held.

- [ ] **Scrub `MDE_*` env vars in direct-API mode**, not just agent
      mode (`src/main.rs` direct path vs `clear_env` in agent path).
      For long-running invocations the secret is visible via
      `ps -E` / `/proc/<pid>/environ` until process exit. Reviewer
      flagged as Low.

### Compatibility

- [ ] **Locale-translated Keychain errors** in `classify_keyring_err`
      (`src/config/credential_store.rs`). The string-match allowlist
      ("no default keychain" etc.) misses Japanese / other locales of
      the same `errSecNoDefaultKeychain` error, causing those users to
      hit the no-toml-fallback branch on a clean machine. Either match
      on `keyring::Error` variants (if exposed) or read the underlying
      OSStatus directly.

- [ ] **Document mid-migration Ctrl-C recovery** in the README. The
      migrate flow is atomic at the tempfile-rename step but Ctrl-C
      between Keychain write and the rewrite leaves both copies present
      (Keychain entry + plaintext toml). Recoverable but not documented.

### DX

- [ ] **Replace emoji** in `set_value` / `delete_value` output with
      plain text to match the rest of the CLI (and the project's
      no-emoji convention in CLAUDE.md). The migrate output already
      avoids them.

- [ ] **Document the credentials.toml search order** in the README.
      The cwd-relative `.mde-credentials.toml` having higher priority
      than `~/.config/mde/credentials.toml` can surprise migrate users.

- [ ] **Improve Keychain ACL error guidance**. When `status` shows
      `error (UNIX[Operation not permitted])`, the user should be
      pointed at the README section explaining how to re-grant access
      via Keychain Access.app's Access Control tab.

- [ ] **Stronger backup-warning callout in README** ("Credential
      storage" section). The migrate warning in the CLI output is
      multi-line warning but the README mention is only one paragraph.
