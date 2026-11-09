# secret_vault development lessons (2026-10 session distillation)

**English** | [中文](lessons-2026-10.zh-CN.md)

> Distilled under the "promote repeated traps" rule: each entry = symptom →
> root cause → **reusable rule**. Source: phase 0–3 implementation + four
> honest-review rounds. Entries marked ⭐ are reused verbatim from
> duckdb-nats-rw's `docs/lessons-2026-10.md` / fix-plan and proved effective
> in this project (no recurrence).

## 1. DuckDB v2.0-dev extension API traps (pin d54cbe3)

1. **Never write header paths from memory.** Symptom: four consecutive rounds
   of compile failures (`buffered_file_reader.hpp` lives under
   `common/serializer/`, not `common/buffer/`; `uuid.hpp` under
   `common/types/`; `binary_deserializer.hpp`/`main/config.hpp` missing).
   Rule: before writing includes, batch-verify **all** of them against the
   pinned source tree with `find src/include -name "<basename>"` — don't fix
   one and rebuild per round.
2. **Read the .gram file for syntax questions.** In `CREATE PERSISTENT SECRET
   name IN <storage> (OPTIONS)` the IN clause comes **before** the
   parentheses — settled by reading
   `src/parser/peg/grammar/statements/create_secret.gram` after the parser
   error. Rule: PEG grammar files are authoritative for SQL syntax doubts;
   never guess.
3. **Table functions must terminate explicitly.** Symptom: status() queries
   hung forever (with a bad key they didn't hang — only the happy path got
   there). Rule: one-shot table functions must emit their row and finish with
   `SetCardinality(0)`; the done flag belongs in `GlobalTableFunctionState`
   (`data.bind_data->Cast<T>()` returns a const reference, so bind data can't
   hold mutable state).
4. **The table-function named-argument API changed.** `.named_parameters` no
   longer exists; use `FunctionSignature().AddPositionalOnly("x", type)` +
   `GetSignature().WithTypedKwargs("options", [](TypedKwargs &o){ o.Add("k",
   type); })`; the bind side still reads `input.named_parameters`.
5. **Extension setting registration**: `DBConfig::AddExtensionOption(name,
   desc, LogicalType, default, callback, SetScope)`; the callback is a
   **function pointer** `void(*)(ClientContext&, SetScope, Value&)`. RESET
   re-invokes the callback with the default value (measured; do not infer
   "RESET skips the callback" from ResetOption source — CR-H5 false-positive
   lesson).
6. **`secret.GetName()` returns an Identifier** (not a string); use
   `GetName() + suffix` uniformly for AAD/paths and derive the base name back,
   and maintain an `identifier_map_t<string>` (normalized → original) to
   prevent case-normalization from breaking AAD consistency.
7. **SecretStorage extension point**: subclass `CatalogSetSecretStorage`
   (copy the `LocalFileSecretStorage` + `DefaultSecretGenerator` pattern,
   replacing path/suffix/storage_mode); register via the public
   `SecretManager::LoadSecretStorage`; reachable through
   `DBConfig::GetConfig(db).secret_manager`.
8. **In-memory serialization uses `MemoryStream`** (WriteStream + ReadStream
   combined); whole-file reads use `BufferedFileReader::FileSize()+ReadData()`.
9. **Dev-build extension version strings come from the building repo's git
   describe** → cross-repo dev extension loading requires
   `SET allow_extensions_metadata_mismatch=true` (official community CI
   builds are unaffected).

## 2. Build & remote operations (Windows workstation + minis Docker)

10. ⭐ **LF enforcement** (.gitattributes), ⭐ **cbindgen header-freshness
    build gate**, ⭐ **timeout + bounded logs + BUILD_EXIT marker polling for
    build/test commands**, ⭐ **reldebug instead of debug** (ASan storm) — all
    inherited from nats_rw; zero recurrence in this project.
11. **docker cp is unreliable on this host**: one failed transaction zeroed a
    file inside the container; a subsequent cp to the same path reported
    success but was still empty, and the host-side file also vanished at one
    point. Rule: get files into containers via
    `docker exec -i <c> bash -c 'cat > path' < local-file` + **md5
    verification on both sides**.
12. `docker exec bash -s` needs `-i` to consume stdin; the image's PATH lacks
    `/usr/local/cargo/bin` — explicitly `export PATH=/usr/local/cargo/bin:$PATH`
    before every exec.
13. **Cross-container networking via `docker network connect`** (the builder
    joins `nats-rw_default` and reaches NATS by service name). The local
    machine has no direct GitHub access (git https blocked): duckdb sources
    were copied from an existing tree (no external network); web content via
    WebFetch, with raw.githubusercontent often resetting (switch web reader).

## 3. Test & script traps (highest-frequency pitfall zone)

14. **Run unittest one .test file at a time**: multiple .test path arguments
    get **concatenated into a single filter** yielding "No test cases
    matched". `.test` runs need env (KEY/PASSPHRASE) injected and an isolated
    HOME.
15. **CLI `-list` output contains every statement's result**: multi-statement
    value extraction sucks in noise lines like `true` (E3 root cause). Rule:
    get single values via a dedicated query or `| tail -1`.
16. **`set -o pipefail` swallows assertions**: `(cmd|grep) && echo PASS` never
    prints PASS when cmd exits nonzero, yet hides inside FAIL:0 fake green
    (B7a lesson). Rule: first `OUT=$(cmd 2>&1 || true)`, then
    `if echo "$OUT"|grep -q`; **assertions must print a visible PASS**.
17. **Per-command-process helpers keep SET from surviving across commands**
    (E1's first round tested the default). Rule: session-scoped semantics
    (SET / temp objects) must complete inside a single `-c` multi-statement.
18. **Cross-round residue breaks reproducibility**: NATS stream-name reuse
    accumulated messages (1→3); an old bundle (644) hit CREATE_NEW. Rule:
    timestamp test resources (stream names / file paths), or pre-clean +
    idempotent AND **safe** overwrite (see 21).
19. **local_file same-name CREATE conflicts across processes**: if the file
    exists you get "already exists" — construct conflict scenarios by cp'ing
    a source file, not by re-CREATE.
20. **Batch text replacement hits "intentional values"**: once batch-replaced
    the deliberately wrong code `A×52` into the correct code. Rule: batch
    replacements need an explicit exclusion list.
21. **Watch for fixes introducing worse semantics (r11 double case)**: export
    idempotence → unconditionally deleting arbitrary existing files (later:
    overwrite only empty files / valid magic); rotate env restore →
    empty-string degradation (later: distinguish unsetenv). Rule: **verify
    target identity before destructive operations**; "restore the original
    state" must distinguish "originally existed" from "originally absent".

## 4. Rust/C++ boundary

22. **FFI-returned buffers must carry the real capacity**:
    `Vec::from_raw_parts(ptr,len,len)` with cap≠len is allocator UB (honest
    review round 1, HIGH-1). The struct carries a `cap` field; the contract
    is written into the header comments.
23. **`Zeroizing<GenericArray>` does not satisfy Zeroize**: keys are uniformly
    `Zeroizing<[u8;32]>`, `Aes256Gcm::new(Key::from_slice(&*key))`.
24. **staticlib produces no rlib**: integration tests need
    `crate-type=["staticlib","rlib"]` (corrosion's explicit
    `--crate-type=staticlib` is unaffected).
25. **Anonymous-namespace structs cannot cross TUs**: shared RAII/helpers go
    in headers (e.g. VaultBufGuard). Zeroizing a const bind string requires
    `const_cast`.
26. **cargo test parallelism shares process env** → a same-name Mutex
    (ENV_LOCK) serializes all env-mutating cases; env-dependent integration
    tests go in separate tests/ binaries.
27. **Verify arithmetic on the spot**: 32B=256bit → base32 is **52**
    characters, not 56 (an assertion stayed wrong for a round).

## 5. Honesty process (methodology distilled from six review rounds)

28. **Fixes themselves must be re-reviewed**: r9/r11 introduced new problems
    during fixes (see 21). After each fix round: full regression + at least
    one new negative scenario targeting the fix itself (e.g. E2e).
29. **Source-code inference can be overturned by measurement** (CR-H5 RESET
    false positive): conclusions that can be measured must not stay at
    read-the-code inference; false positives must be explicitly retracted and
    turned into standing regressions, never quietly dropped.
30. **Claim precision is bounded by evidence**: "acceptance 7 all achieved"
    was judged overloaded because of one untested negative (replay); "FAIL:0"
    once masked never-triggered assertions (16). Rule: summary assertions =
    visible PASS line count + naming each scenario, never counting "didn't
    fail".
31. **Error paths are systematically under-tested**: every leak/half-failure
    issue sat in an exception branch (deserialize throw / disk IO failure /
    rotate mid-failure) — all-green happy-path tests could not find them.
    Rule: during review, read the catch blocks specifically; leak issues go
    onto an ASan-quantification debt list, not closed by "the code looks
    right".
32. **Derive test expectations from implementation semantics, not intuition**
    (HC7-H1): the "a write enters the snapshot immediately" intuition vs the
    actual "erase-invalidates" design — falsified on the first run. Rule:
    read the path's state-maintenance code before writing reload/snapshot
    assertions; never-run tests stay labeled "not executed", never written up
    as "executed in sync".
33. **Fixes themselves must be re-reviewed (evidence #2)**: r11 idempotence
    introduced destructive deletion, the r13 KEY_OLD cache introduced an
    undeclared key-residency change, and the first fleet-verify round after
    r11 exposed a poisoning gap — every fix round's new code/tests introduce
    new risk surfaces; fix rounds must carry their own targeted
    negative/boundary cases.
34. **Plan documents drift silently** (file lists naming nonexistent files /
    new scripts missing / stale function signatures and wording): do a
    plan↔code two-way list check at every phase end (two dedicated review
    rounds each caught 8–9 issues); the revisions chain is the only
    trustworthy audit trail; major scope decisions (cutting fleet / deferring
    replay to v1.1) must be written back to the plan the same day.
    **Completion checklist (solidified after the HC9 triple evidence)**:
    before declaring "done", tick off item by item — ① every status-claiming
    file (README status block / UPDATING counts / plan todo items) matches
    the facts; ② new tests were executed and revisions written to disk;
    ③ containers/artifacts show no drift from HEAD (md5). The drift triple:
    r14 stalled at "to be restored", r10 mis-recorded "executed in sync",
    README/UPDATING lagged two generations.
