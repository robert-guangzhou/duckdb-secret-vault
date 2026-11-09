# duckdb-secret-vault

**English** | [中文](README.zh-CN.md)

The `secret_vault` DuckDB extension provides **encrypted** local storage
(storage name `local_encrypted`) for `CREATE PERSISTENT SECRET`, replacing the
plaintext on-disk format of DuckDB's default `local_file` storage.

## Why

By default DuckDB writes persistent secrets to `~/.duckdb/stored_secrets` as
**plaintext binary** — disk theft, a leaked backup, or another account on a
shared host can read your S3 keys, database passwords, or NATS credentials
directly. This extension registers an alternative storage `local_encrypted`:
every secret is written as AES-256-GCM ciphertext (per-file random nonce, AEAD
tag bound to the secret name — rename/tamper fails loudly at decryption), files
keep 600 permissions, and the encryption key never touches disk. Because it
encrypts DuckDB's own serialization blob, it works transparently with any
secret type (s3 / mysql / postgres / nats_rw / ...).

## Status

v1.1 feature-complete: encrypted storage (keyring/passphrase/env key
providers) + operations functions (`secret_vault_migrate/rotate/export/import/
status/reload`) + one-time encrypted envelopes for cross-instance transfer
(hidden stdin code entry, replay protection) + fleet enhancements (hot reload /
KEY_OLD rotation transition). Community-extension submission in preparation.

## Quick start

```sql
-- available once the community PR is accepted: INSTALL secret_vault FROM community;
LOAD secret_vault;                         -- dev builds: LOAD by path, CLI needs -unsigned

-- choose where the encryption key lives: keyring (default) | passphrase | env
SET secret_vault_provider = 'env';         -- e.g. SECRET_VAULT_KEY injected by your scheduler

-- persistent secrets are now written encrypted (DSVLT magic + AES-256-GCM)
CREATE PERSISTENT SECRET my_s3 IN local_encrypted (
    TYPE s3, KEY_ID 'AKIA...', SECRET 'shhh', REGION 'us-east-1');

-- fresh processes auto-load; duckdb_secrets() still redacts
SELECT name, storage, secret_string FROM duckdb_secrets();

-- or make it the default storage (CREATE without IN routes here)
SET default_secret_storage = 'local_encrypted';
```

## Key providers

| provider | where the key lives | key on disk? |
|---|---|---|
| `keyring` (default) | OS credential store (Windows Credential Manager / macOS Keychain / Linux Secret Service); random 256-bit master key generated on first use | no; on Linux without a Secret Service it errors out instead of silently downgrading |
| `passphrase` | human memory; derived via Argon2id (m=64MiB, t=3, p=1) with a per-file random salt | no |
| `env` (unattended) | injected per run by your scheduler/CI as `SECRET_VAULT_KEY` (base64 32B) | no (process env only) |

## Key generation guide (read before deploying)

- **env provider** (schedulers/CI): `export SECRET_VAULT_KEY="$(openssl rand
  -base64 32)"` — inject it from the scheduler's credential store; **never**
  hard-code it in scripts or task definitions. Same-user processes reading
  `/proc/<pid>/environ` is a declared threat boundary (see
  [THREAT-MODEL](docs/THREAT-MODEL.md)).
- **keyring provider** (workstation default): nothing to generate — a random
  256-bit master key is created in the OS credential store on first use.
  Rotating the master key = clear the `duckdb.secret_vault/master` entry, then
  `secret_vault_rotate` (long-lived processes cache the master key and must be
  restarted after rotation).
- **passphrase provider**: use ≥4 random words or a ≥16-char random string;
  weak passphrases can be brute-forced offline (Argon2id raises per-guess cost
  but is no substitute for entropy); **a forgotten passphrase means the data
  is unrecoverable**.
- The envelope one-time code: shown once in the export result row; hand it
  over via a password manager or verbally; re-exporting invalidates the old
  bundle.
- **import is immediately visible** (v1.1): after import lands on disk the
  current process can use the secrets right away (hot reload runs internally).
- **KEY_OLD rotation transition** (v1.1, env provider only): during a key
  change window set `SECRET_VAULT_KEY_OLD=<old key>` to keep reading old
  ciphertext. Rotation runbook: ① deploy {KEY=new, KEY_OLD=old} everywhere and
  restart → ② publish new ciphertext (`secret_vault_rotate` or rewrite the
  directory) → ③ observation window → ④ remove KEY_OLD.

## Operations

```sql
LOAD secret_vault;
SET secret_vault_provider = 'env';              -- or keyring (default) / passphrase
CREATE PERSISTENT SECRET s IN local_encrypted (TYPE s3, ...);
SELECT * FROM secret_vault_status();
SELECT * FROM secret_vault_migrate();           -- plaintext local_file -> encrypted (source kept by default)
SELECT * FROM secret_vault_rotate(new_provider := 'env');
SELECT * FROM secret_vault_export('/tmp/b.svb'); -- one-time code shown in the result row
SELECT * FROM secret_vault_import('/tmp/b.svb'); -- reads the code from stdin (hidden echo) by default; code := '...' for automation (lands in SQL history)
SELECT * FROM secret_vault_reload();             -- hot reload: rescan the directory (adds/updates/removes aligned; corrupt files aggregated in one report)
```

## Semantics & assumptions (must read)

- `secret_vault_migrate` errors on a name conflict by default; pass
  `on_conflict := 'overwrite'|'skip'` explicitly. Source files must have 600
  permissions.
- `secret_vault_rotate` is two-pass: any read-phase failure leaves disk
  untouched; **a mid-write failure leaves a mixed old/new-key state** (the
  process automatically restores the old provider and old env key) — recovery:
  re-SET the old passphrase/key and rotate again.
- The `secret_vault_export` envelope file lands with 600 permissions (it
  carries all secrets' plaintext, protected only by the one-time code).
- The passphrase interactive prompt appears only when stdin is a tty and no
  env var is set; **input echo is hidden** (v1.1; if termios/SetConsoleMode
  cannot disable echo it degrades to visible input and prints a WARNING).
  Concurrent prompts from multiple connections are undefined behavior
  (single-session design).
- Close active queries/connections using the secrets before
  `secret_vault_reload` (reload rebuilds the storage's catalog; active queries
  holding old entries are undefined).
- `secret_vault_provider` is a **process-global** setting: once any session
  SETs it, it applies process-wide; concurrent SETs of different values are
  undefined (designed for single-session / single-scheduler use).
- The storage assumes a **single DatabaseInstance**; if you attach multiple
  databases in one process and LOAD in each, settings and status reflect only
  the last registered instance.
- `SECRET_VAULT_DIRECTORY` may select the storage directory before LOAD
  (default `~/.duckdb/stored_secrets_vault`); at runtime use
  `SET secret_vault_directory` (only allowed while the storage is empty).
- Set env vars (`SECRET_VAULT_KEY/PASSPHRASE`) before process start; mutating
  env concurrently with queries is undefined (Rust env access is not
  thread-safe).
- Crashes may leave `<name>.duckdb_secret.vault.tmp-<uuid>` temp files: they
  are never loaded and are safe to delete manually (`rm *.tmp-*`).

## Known boundary

If a secret file is corrupted (tampering / leftover from a bad key),
`CREATE OR REPLACE` fails during lazy loading; the only recovery is to
**manually delete that secret file and re-create it** (same semantics as a
corrupted local_file secret).
