# Threat Model (secret_vault v0.1)

**English** | [中文](THREAT-MODEL.zh-CN.md)

This document declares the security boundary of the `secret_vault` extension;
it pairs with chapter 6 (security considerations) of the dev plan.

## Assets & protected objects

- The on-disk secret files written by DuckDB `CREATE PERSISTENT SECRET`
  (credentials: s3 keys, database passwords, NATS credentials, ...) at
  `~/.duckdb/stored_secrets_vault/<name>.duckdb_secret.vault`.
- The one-time transport-envelope bundle file of `secret_vault_export()`
  (carries all secrets' plaintext, protected only by a single-use 256-bit
  transport key).

## In scope (what this extension defends against)

| threat | mechanism |
|---|---|
| Whole-disk theft / disk imaging | AES-256-GCM encryption at rest; the key is not on disk (see key sources) |
| Backup leakage (ciphertext backed up too) | same — backups only ever see ciphertext |
| Reads by **other OS users** on a shared host | ciphertext + 600 file permissions (`FILE_FLAGS_PRIVATE`); privacy is verified before reading |
| Secret file tampered / swapped / renamed | AEAD tag + AAD binding (40-byte header + secret name); decryption fails loudly |
| Envelope intercepted in transit | bundle contains no plaintext and no exporter key material at the byte level; full-entropy one-time code (52-char base32) |
| Accidental plaintext residue | serialization plaintext / decrypted plaintext / code / passphrase buffers are zeroized after use (see "known residuals") |

## Key sources & at-rest properties

| provider | key custody | key on disk? |
|---|---|---|
| `keyring` (default) | OS credential store (Windows Credential Manager / macOS Keychain / Linux Secret Service); random 256-bit master key generated on first use | no (keychain-internal storage; on Linux without a Secret Service it errors out instead of downgrading) |
| `passphrase` | human memory; Argon2id (m=64MiB, t=3, p=1) derivation with a per-file random salt | no |
| `env` (unattended) | injected per run by the scheduler as `SECRET_VAULT_KEY` (base64 32B; generate: `openssl rand -base64 32`) | no (process env only) |

Passphrase strength requirement: ≥4 random words or a ≥16-char random string;
weak passphrases can be brute-forced offline (Argon2id raises the per-guess
cost but is no substitute for entropy).

## Out of scope (explicitly not defended; same boundary as ssh-agent / tresor)

1. **Arbitrary code running as the same OS user**: it can simply call DuckDB
   to read the decrypted secrets, or read process memory / env
   (`/proc/<pid>/environ`, `ps eww`).
2. **root / administrators**: can read the OS keychain and process memory.
3. **Process memory dumps / core dumps**: decrypted secrets live in process
   memory.
4. **Forgotten passphrase**: no backdoor (a backdoor is a leak surface); the
   files are permanently unrecoverable.
5. **Same-user side channels**: stdin code entry has hidden echo (v1.1);
   leaking the one-time code via clipboard/chat history is an operational
   risk — hand it over through a password manager.

## Known residuals (honesty statement)

- **The keyring master key stays in process memory** (OnceLock cache since
  r13, introduced by the CR-H4 fix): the old implementation read it from the
  keychain into a Zeroizing buffer on every derivation; the new one caches it
  in process static storage for the **whole process lifetime without
  zeroizing**. This is defensible under the threat model (same-user attackers
  are out of scope; the keychain itself is persistent storage anyway), but the
  key-residency window widens from "moment of use" to "process lifetime" —
  after externally rotating the keyring master key, the process must be
  restarted for it to take effect.
- **Intermediate buffers** during MemoryStream growth were not zeroized
  (length and capacity were); resolved in v1.1 by ZeroizingMemoryStream.
- Zeroization on error paths is guaranteed by RAII guards; ASan-grade leak
  quantification was not done (the build host has a history of ASan storms;
  an RSS-heuristic loop was used instead, and conclusions are labeled as
  heuristic).
- A mid-write failure of `secret_vault_rotate` leaves a mixed old/new-key
  directory (the process auto-restores the old provider/env; recovery steps in
  the README). In extreme cases, manually re-SET the old passphrase and retry.
- Since v1.1 envelopes carry a per-entry mtime, and import rejects entries
  older than existing files by default (anti-replay); entries whose **target
  does not exist** have no time reference and get no replay check.
- **KEY_OLD rotation transition window** (v1.1, env provider):
  `SECRET_VAULT_KEY_OLD` is full-power key material coexisting with the main
  key in process env until removed — during the window the old boundary
  "old-key leak = all old ciphertext leaked" still holds; the removal step is
  a mandatory end of the runbook.
- Passphrase interactive input has hidden echo (v1.1,
  termios/SetConsoleMode); if disabling echo fails it degrades to visible
  input and prints a WARNING (never silently).
