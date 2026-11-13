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

## What's on disk: plaintext vs local_encrypted (real examples)

The same three secrets (postgres / mysql / s3) were created twice with
identical values — first into DuckDB's default `local_file`, then into
`local_encrypted`. Below are real `od` hex dumps of the resulting files
(credentials are throwaway test values). Plaintext sizes → vault sizes grow
by exactly +56 bytes: 8-byte magic + 2-byte version + 1-byte provider +
1-byte flags + 16-byte salt + 12-byte nonce + 16-byte AEAD tag.

### postgres

`local_file` `pg_plaintext.duckdb_secret` (488 B) — the password is readable
by anyone who can read the disk:

```text
000000  64 00 08 70 6f 73 74 67 72 65 73 65 00 06 63 6f  >d..postgrese..co<
000010  6e 66 69 67 66 00 0c 70 67 5f 70 6c 61 69 6e 74  >nfigf..pg_plaint<
...                                                       (KV map region)
000010  ff ff 65 00 00 66 00 17 50 30 73 74 67 72 65 73  >..e..f..P0stgres<
000020  2d 53 65 63 72 65 74 2d 50 57 2d 32 30 32 36 ff  >-Secret-PW-2026.<
        └────────── password in cleartext ──────────────┘
```

`local_encrypted` `pg_encrypted.duckdb_secret.vault` (544 B) — DSVLT header
+ AES-256-GCM ciphertext, zero credential bytes anywhere in the file:

```text
000000  44 53 56 4c 54 00 00 00 00 01 03 00 00 00 00 00  >DSVLT...........<
        └magic┘          └ver┘└pr┘└fl┘└── salt (16B, zeroed for env provider)
000010  00 00 00 00 00 00 00 00 00 00 00 00 99 45 f7 b9  >.............E..<
                                            └─ nonce(12B)─┘└── ciphertext ──
000020  b4 d5 8d d2 47 44 03 70 1f 3d e8 e4 3b 3e 63 10  >....GD.p.=..;>c.<
...                                                       (ciphertext + tag)
000220                                                      end of file (tag)
```

### mysql

`local_file` (433 B): password at file offset 259 in cleartext —

```text
000010  ff ff 65 00 00 66 00 14 4d 79 53 71 6c 2d 53 65  >..e..f..MySql-Se<
000020  63 72 65 74 2d 50 57 2d 32 30 32 36 ff ff ff ff  >cret-PW-2026....<
```

`local_encrypted` (489 B):

```text
000000  44 53 56 4c 54 00 00 00 00 01 03 00 00 00 00 00  >DSVLT...........<
000010  00 00 00 00 00 00 00 00 00 00 00 00 bf 55 a6 98  >.............U..<
000020  ea 9e 27 26 a9 0d 5f 39 4d d6 03 7a c8 c1 25 91  >..'&.._9M..z..%.<
...ciphertext...
0001e0  24 01 60 73 90 b5 c3 d2 ca                       >$.`s.....<
```

### s3 (MinIO-compatible)

`local_file` (494 B) — secret key in cleartext; even the bucket scope is
plain metadata (`s3://`):

```text
000000  64 00 02 73 33 65 00 06 63 6f 6e 66 69 67 66 00  >d..s3e..configf.<
000010  0c 73 33 5f 70 6c 61 69 6e 74 65 78 74 67 00 03  >.s3_plaintextg..<
000020  05 73 33 3a 2f 2f 06 73 33 6e 3a 2f 2f 06 73 33  >.s3://.s3n://.s3<
...
000000  66 00 06 73 65 63 72 65 74 ff ff 64 00 64 00 19  >f..secret..d.d..<
000010  ff ff 65 00 00 66 00 18 73 33 63 72 33 74 2d 50  >..e..f..s3cr3t-P<
000020  6c 61 69 6e 74 65 78 74 2d 50 57 2d 32 30 32 36  >laintext-PW-2026<
```

`local_encrypted` (550 B):

```text
000000  44 53 56 4c 54 00 00 00 00 01 03 00 00 00 00 00  >DSVLT...........<
000010  00 00 00 00 00 00 00 00 00 00 00 00 42 ba f5 8b  >............B...<
000020  fb fe e6 8e c0 b9 eb 0b fb c4 9f 23 65 44 2f f1  >...........#eD/.<
...ciphertext...
000220  1e 03 ee fd d2 04                                >......<
```

String-search check across the six files: each plaintext file contains its
credential exactly once; the three vault files contain **zero** occurrences.

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

### Envelope transfer, end to end (captured session)

How the one-time code appears, how it is entered, and what one-time really
means — the transcript below is a real captured session (two DuckDB
processes on different hosts with different key systems).

**Instance A (exporter, env provider)** — create two secrets, then export:

```sql
CREATE PERSISTENT SECRET s3_creds IN local_encrypted (TYPE s3, KEY_ID 'AKIAEXAMPLE', SECRET 'shhh-s3-secret', ENDPOINT 'minio.example:9000', REGION 'us-east-1');
CREATE PERSISTENT SECRET pg_creds IN local_encrypted (TYPE postgres, HOST 'pg.example', DATABASE 'app', USER 'etl', PASSWORD 'shhh-pg-secret');
SELECT * FROM secret_vault_export('/tmp/b.svb');
```

The one-time transport code is displayed **once, in the result row** — this
is the only moment it ever appears:

```text
┌────────────┬──────────────────────────────────────────────────────┬─────────┐
│    file    │                   transport_code                     │ secrets │
├────────────┼──────────────────────────────────────────────────────┼─────────┤
│ /tmp/b.svb │ JTTEWOKCUSKY6VPYV2PN3LW3CFSAJG6VHPLDKZ664WQ4US3B6KJA │       2 │
└────────────┴──────────────────────────────────────────────────────┴─────────┘
              52-char base32, full entropy — hand it over via a password
              manager or verbally; it is NOT in the file, only this row
```

Copy `/tmp/b.svb` to instance B over any channel (the file itself contains
no plaintext and no key material).

**Instance B (importer — different key system: passphrase, no
`SECRET_VAULT_KEY`)** — run the import and type/paste the code at the
prompt (echo is hidden on a real terminal):

```text
$ duckdb -unsigned -c "LOAD secret_vault; SET secret_vault_provider='passphrase';
                       SELECT * FROM secret_vault_import('/tmp/b.svb');"
secret_vault: enter transport code: ██████████████████████████   ← typed blind, then Enter
┌──────────┬─────────┐
│ imported │ skipped │
├──────────┼─────────┤
│        2 │       0 │
└──────────┴─────────┘
```

The imported secrets are immediately usable in B and are **re-encrypted
under B's own key system** (env on A → passphrase on B; A's key never
travels):

```text
SELECT name, storage, secret_string FROM duckdb_secrets();
pg_creds|local_encrypted|...;password=redacted;user=etl
s3_creds|local_encrypted|...;secret=redacted;key_id=AKIAEXAMPLE
```

**What "one-time" means (real negative checks):**

- Re-exporting on A seals a **new** code and invalidates the old bundle:
  a fresh instance C importing with the *old* code fails
  `vault open failed: AEAD tag mismatch (wrong key, wrong secret name, or
  tampered file)`; with the *new* code it succeeds (`imported = 1`).
- Importing secrets that already exist errors with
  `secret '...' already exists (use on_conflict := 'overwrite' or 'skip')`.

**Automation (scripts only):** the code can be passed explicitly —
`SELECT * FROM secret_vault_import('/tmp/b.svb', code := '<52 chars>');`
— but be aware it then lands in SQL history; prefer stdin
(`echo "$CODE" | duckdb ... `) for anything interactive.

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
