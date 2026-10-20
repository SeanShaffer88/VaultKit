# VaultKit — agent notes

- Zero dependencies is a design rule: DPAPI and Credential Manager are reached through hand-declared bindings in src/platform.rs (each extern block carries its #[link] library: advapi32 for Cred*, crypt32 for DPAPI, kernel32). Do not add a windows-binding dependency without a written justification.
- Secrets are never logged, never returned by listing, and never stored except as DPAPI blobs (entropy = the entry's target name). Any change that weakens that rule needs explicit justification in the PR.
- Validation rules (namespace/key/secret limits in src/lib.rs) are contractual — they keep target names valid as credential targets and enumeration filters. Changing them is a breaking API change.
- Off-Windows builds must keep the FFI contract testable: platform stubs return ERR_NOT_SUPPORTED; the real roundtrip proof is tests/roundtrip.rs, which runs natively on Windows CI.
- Gate: WinDevKit tools/gate.sh (fmt + clippy both targets + full tests). Check/clippy do not link — CI's real build is the link gate.
