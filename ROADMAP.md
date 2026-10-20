# VaultKit Roadmap

## v0.1 (current)
DPAPI + Credential Manager storage behind the C ABI: put / get / delete / exists / list-metadata, namespaced entries, validation, precise errors, native Windows roundtrip test in CI.

## Candidates
- **Machine-scope storage** (LocalMachine DPAPI + appropriate ACLs) for services that run as SYSTEM — only with an explicit opt-in flag; the default stays CurrentUser.
- **Change notifications**: watch a namespace for put/delete (useful for live-reload of credentials).
- **Per-entry metadata** via credential attributes (comment, expiry) once there is a caller who needs it — the attribute API is unused in v0.1 deliberately.
- **Import/export**: sealed export (DPAPI-protected bundle) for moving entries between machines of the same user with an explicit re-protect step.
- **Language bindings**: thin .NET and Python wrappers over the C ABI, in separate repos if demand appears.

## Explicitly not planned
- A network or sync component. Secrets stay on the machine, in the OS store.
- Storing non-secret configuration — that is a settings library's job.
