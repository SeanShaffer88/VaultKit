//! VaultKit — pure logic core: name validation, target naming, JSON.
//! Platform access (DPAPI + Credential Manager) lives in [`platform`];
//! the C ABI lives in [`ffi`].
//!
//! Storage model: each secret is one Windows generic credential whose
//! target is `VaultKit/<namespace>/<key>`, and whose blob is the secret
//! additionally DPAPI-protected (CurrentUser, UI forbidden) with the
//! target name as entropy — so the stored bytes are bound to this user,
//! this machine, and this exact entry name.

pub mod ffi;
pub mod platform;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

pub const VK_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;

/// Secrets are capped so DPAPI output stays well under the Credential
/// Manager generic-blob limit (2560 bytes) with room for DPAPI overhead.
pub const MAX_SECRET_BYTES: usize = 2000;
pub const MAX_NAMESPACE_LEN: usize = 64;
pub const MAX_KEY_LEN: usize = 128;

pub type VResult<T> = Result<T, (i32, String)>;

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn validate_component(
    what: &str,
    value: &str,
    max_len: usize,
    allow: impl Fn(char) -> bool,
) -> VResult<()> {
    if value.is_empty() {
        return Err((ERR_INVALID_ARG, format!("{what} must not be empty")));
    }
    if value.chars().count() > max_len {
        return Err((
            ERR_INVALID_ARG,
            format!("{what} exceeds {max_len} characters"),
        ));
    }
    if value == "." || value == ".." {
        return Err((ERR_INVALID_ARG, format!("{what} must not be '{value}'")));
    }
    for c in value.chars() {
        if c.is_control() || !allow(c) {
            return Err((
                ERR_INVALID_ARG,
                format!("{what} contains a disallowed character: {c:?}"),
            ));
        }
    }
    Ok(())
}

/// Namespaces are conservative: letters, digits, dot, dash, underscore.
/// (They become part of a credential target and an enumeration filter.)
pub fn validate_namespace(ns: &str) -> VResult<()> {
    validate_component("namespace", ns, MAX_NAMESPACE_LEN, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
    })
}

/// Keys are broader (tokens, ids, emails) but exclude the characters
/// that are separators or filter wildcards in the credential store.
pub fn validate_key(key: &str) -> VResult<()> {
    validate_component("key", key, MAX_KEY_LEN, |c| {
        !matches!(c, '/' | '\\' | '*' | '?')
    })
}

pub fn validate_secret(secret: &str) -> VResult<()> {
    if secret.len() > MAX_SECRET_BYTES {
        return Err((
            ERR_INVALID_ARG,
            format!(
                "secret is {} bytes; the limit is {MAX_SECRET_BYTES}",
                secret.len()
            ),
        ));
    }
    Ok(())
}

/// The credential target name for (namespace, key). Inputs are validated
/// first by callers; this just formats.
pub fn target_name(namespace: &str, key: &str) -> String {
    format!("VaultKit/{namespace}/{key}")
}

/// The enumeration filter for a namespace (or all VaultKit entries).
pub fn filter_for(namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) => format!("VaultKit/{ns}/*"),
        None => "VaultKit/*".to_string(),
    }
}

/// Split a target name back into (namespace, key); None when the target
/// is not a VaultKit entry.
pub fn parse_target(target: &str) -> Option<(String, String)> {
    let rest = target.strip_prefix("VaultKit/")?;
    let (ns, key) = rest.split_once('/')?;
    if ns.is_empty() || key.is_empty() {
        return None;
    }
    Some((ns.to_string(), key.to_string()))
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntryInfo {
    pub namespace: String,
    pub key: String,
    pub last_written_unix: Option<i64>,
}

impl EntryInfo {
    pub fn to_json(&self) -> String {
        let mtime = match self.last_written_unix {
            Some(m) => m.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"namespace\":\"{}\",\"key\":\"{}\",\"last_written_unix\":{}}}",
            json_escape(&self.namespace),
            json_escape(&self.key),
            mtime
        )
    }
}

pub fn list_json(entries: &[EntryInfo]) -> String {
    let mut s = String::from("[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&e.to_json());
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rules() {
        assert!(validate_namespace("my-app.prod_2").is_ok());
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("has space").is_err());
        assert!(validate_namespace("a/b").is_err());
        assert!(validate_namespace("..").is_err());
        assert!(validate_key("user@example.com").is_ok());
        assert!(validate_key("tok:abc-123").is_ok());
        assert!(validate_key("a/b").is_err());
        assert!(validate_key("wild*card").is_err());
        assert!(validate_key("").is_err());
        assert!(validate_secret(&"x".repeat(MAX_SECRET_BYTES)).is_ok());
        assert!(validate_secret(&"x".repeat(MAX_SECRET_BYTES + 1)).is_err());
    }

    #[test]
    fn naming_roundtrip() {
        let t = target_name("app", "api-key");
        assert_eq!(t, "VaultKit/app/api-key");
        assert_eq!(
            parse_target(&t),
            Some(("app".to_string(), "api-key".to_string()))
        );
        assert_eq!(parse_target("Other/app/key"), None);
        assert_eq!(filter_for(Some("app")), "VaultKit/app/*");
        assert_eq!(filter_for(None), "VaultKit/*");
    }
}
