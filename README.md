# VaultKit

**Stop storing tokens in plaintext files.** VaultKit is a tiny Windows DLL (with a C header) that gives any app a five-function secret store backed by the operating system:

```c
vk_put("myapp", "api-token", secret);   // store or overwrite
char *s = vk_get("myapp", "api-token"); // fetch (free with vk_free_string)
vk_exists("myapp", "api-token");        // 1 / 0
vk_delete("myapp", "api-token");        // remove
char *j = vk_list_json("myapp");        // metadata, never secrets
```

## How it stores

Each secret is one **Windows generic credential** named `VaultKit/<namespace>/<key>` in Credential Manager. Before the blob is handed to the credential store it is additionally **DPAPI-protected** (CurrentUser scope, UI forbidden) using the target name as entropy — so the stored bytes are bound to this user, this machine, and this exact entry name, and copying the credential store elsewhere yields nothing readable. Plaintexts are never logged. `vk_list_json` returns metadata only (`namespace`, `key`, `last_written_unix`) — it is impossible to enumerate secret values through this API.

## Rules and limits

| Thing | Rule |
|---|---|
| namespace | 1–64 chars: letters, digits, `.` `-` `_` |
| key | 1–128 chars; no `/ \ * ?` or control characters |
| secret | UTF-8, up to 2000 bytes |

Errors are precise: `VK_ERR_NOT_FOUND` for a missing key (including delete), `VK_ERR_ACCESS_DENIED`, `VK_ERR_INVALID_ARG` with a message naming the broken rule. `vk_exists` returns `-1` on platform error so 0/1 are never ambiguous.

## Using it

Link `vaultkit.dll` + the generated import library, include `include/vaultkit.h`. Strings are UTF-8; every returned `char*` is freed with `vk_free_string`.

## Building

```
cargo build --release        # vaultkit.dll on Windows
cargo test --locked          # includes a real DPAPI/CredMan roundtrip on Windows
```

Off Windows, the library builds and its pure-logic and FFI-contract tests run, with storage calls returning `VK_ERR_NOT_SUPPORTED` — the C ABI stays testable anywhere.

## Verification status

Local gate (fmt, clippy on host + windows-msvc targets, full test suite) green. Windows CI runs the roundtrip test **natively**, exercising real DPAPI encryption and Credential Manager storage end to end through the C ABI. What CI cannot cover: interactive Credential Manager UI visibility and multi-user profile behavior — see ROADMAP.md.

License: MIT. No third-party code. See `AGENTS.md` for build discipline.
