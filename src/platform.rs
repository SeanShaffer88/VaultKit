//! Platform layer: DPAPI + Credential Manager on Windows; typed
//! ERR_NOT_SUPPORTED everywhere else (the FFI contract stays testable).
//!
//! Security notes: the secret is DPAPI-protected (CurrentUser scope,
//! UI forbidden) with the target name as entropy before it is handed
//! to CredWriteW, and DPAPI-decrypted on read, so raw credential-store
//! bytes alone do not expose it. Plaintexts are never logged.

#[cfg(not(windows))]
use crate::ERR_NOT_SUPPORTED;
use crate::{EntryInfo, VResult};

#[cfg(not(windows))]
fn not_supported<T>(what: &str) -> VResult<T> {
    Err((
        ERR_NOT_SUPPORTED,
        format!("{what} is only available on Windows"),
    ))
}

#[cfg(not(windows))]
pub fn put(_namespace: &str, _key: &str, _secret: &str) -> VResult<()> {
    not_supported("vault storage")
}
#[cfg(not(windows))]
pub fn get(_namespace: &str, _key: &str) -> VResult<String> {
    not_supported("vault storage")
}
#[cfg(not(windows))]
pub fn delete(_namespace: &str, _key: &str) -> VResult<()> {
    not_supported("vault storage")
}
#[cfg(not(windows))]
pub fn exists(_namespace: &str, _key: &str) -> VResult<bool> {
    not_supported("vault storage")
}
#[cfg(not(windows))]
pub fn list(_namespace: Option<&str>) -> VResult<Vec<EntryInfo>> {
    not_supported("vault storage")
}

#[cfg(windows)]
#[allow(non_snake_case, clippy::upper_case_acronyms)]
mod win {
    use super::*;
    use crate::{parse_target, target_name, ERR_ACCESS_DENIED, ERR_NOT_FOUND, ERR_PLATFORM};
    use std::ffi::c_void;

    // ---- advapi32: Credential Manager ----
    pub const CRED_TYPE_GENERIC: u32 = 1;
    pub const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;

    #[repr(C)]
    pub struct CREDENTIALW {
        pub Flags: u32,
        pub Type: u32,
        pub TargetName: *mut u16,
        pub Comment: *mut u16,
        pub LastWritten: u64, // FILETIME (dwLowDateTime, dwHighDateTime)
        pub CredentialBlobSize: u32,
        pub CredentialBlob: *mut u8,
        pub Persist: u32,
        pub AttributeCount: u32,
        pub Attributes: *mut c_void,
        pub TargetAlias: *mut u16,
        pub UserName: *mut u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn CredWriteW(credential: *const CREDENTIALW, flags: u32) -> i32;
        pub fn CredReadW(
            target: *const u16,
            ty: u32,
            flags: u32,
            credential: *mut *mut CREDENTIALW,
        ) -> i32;
        pub fn CredDeleteW(target: *const u16, ty: u32, flags: u32) -> i32;
        pub fn CredEnumerateW(
            filter: *const u16,
            flags: u32,
            count: *mut u32,
            credentials: *mut *mut *mut CREDENTIALW,
        ) -> i32;
        pub fn CredFree(buffer: *mut c_void);
    }

    // ---- crypt32: DPAPI ----
    #[repr(C)]
    pub struct DATA_BLOB {
        pub cbData: u32,
        pub pbData: *mut u8,
    }
    pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[link(name = "crypt32")]
    extern "system" {
        pub fn CryptProtectData(
            data_in: *const DATA_BLOB,
            data_descr: *const u16,
            entropy: *const DATA_BLOB,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DATA_BLOB,
        ) -> i32;
        pub fn CryptUnprotectData(
            data_in: *const DATA_BLOB,
            data_descr: *mut *mut u16,
            entropy: *const DATA_BLOB,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DATA_BLOB,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
        pub fn GetLastError() -> u32;
    }

    // Well-known Win32 error codes we map precisely.
    const ERROR_NOT_FOUND: u32 = 1168;
    const ERROR_ACCESS_DENIED: u32 = 5;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_err(what: &str) -> (i32, String) {
        let code = unsafe { GetLastError() };
        let mapped = match code {
            ERROR_NOT_FOUND => ERR_NOT_FOUND,
            ERROR_ACCESS_DENIED => ERR_ACCESS_DENIED,
            _ => ERR_PLATFORM,
        };
        (mapped, format!("{what} failed (Win32 error {code})"))
    }

    fn protect(data: &[u8], entropy: &[u8]) -> VResult<Vec<u8>> {
        let input = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let ent = DATA_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut out = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &ent,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_err("CryptProtectData"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData as *mut c_void) };
        Ok(bytes)
    }

    fn unprotect(data: &[u8], entropy: &[u8]) -> VResult<Vec<u8>> {
        let input = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let ent = DATA_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut out = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &ent,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_err("CryptUnprotectData"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData as *mut c_void) };
        Ok(bytes)
    }

    fn read_credential(target: &str) -> VResult<*mut CREDENTIALW> {
        let w = wide(target);
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        let ok = unsafe { CredReadW(w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
        if ok == 0 {
            return Err(last_err("CredRead"));
        }
        Ok(cred)
    }

    /// FILETIME (100ns ticks since 1601) → Unix seconds.
    fn filetime_to_unix(ft: u64) -> Option<i64> {
        const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
        if ft < EPOCH_DIFF_100NS {
            return None;
        }
        Some(((ft - EPOCH_DIFF_100NS) / 10_000_000) as i64)
    }

    pub fn put(namespace: &str, key: &str, secret: &str) -> VResult<()> {
        let target = target_name(namespace, key);
        let blob = protect(secret.as_bytes(), target.as_bytes())?;
        let mut target_w = wide(&target);
        let mut user_w = wide("VaultKit");
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_w.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: 0,
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user_w.as_mut_ptr(),
        };
        let ok = unsafe { CredWriteW(&cred, 0) };
        if ok == 0 {
            return Err(last_err("CredWrite"));
        }
        Ok(())
    }

    pub fn get(namespace: &str, key: &str) -> VResult<String> {
        let target = target_name(namespace, key);
        let cred = read_credential(&target)?;
        let blob = unsafe {
            std::slice::from_raw_parts((*cred).CredentialBlob, (*cred).CredentialBlobSize as usize)
                .to_vec()
        };
        unsafe { CredFree(cred as *mut c_void) };
        let plain = unprotect(&blob, target.as_bytes())?;
        String::from_utf8(plain)
            .map_err(|_| (ERR_PLATFORM, "stored secret is not valid UTF-8".to_string()))
    }

    pub fn delete(namespace: &str, key: &str) -> VResult<()> {
        let target = target_name(namespace, key);
        let w = wide(&target);
        let ok = unsafe { CredDeleteW(w.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            return Err(last_err("CredDelete"));
        }
        Ok(())
    }

    pub fn exists(namespace: &str, key: &str) -> VResult<bool> {
        let target = target_name(namespace, key);
        match read_credential(&target) {
            Ok(cred) => {
                unsafe { CredFree(cred as *mut c_void) };
                Ok(true)
            }
            Err((code, _)) if code == ERR_NOT_FOUND => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn list(namespace: Option<&str>) -> VResult<Vec<EntryInfo>> {
        let filter = crate::filter_for(namespace);
        let w = wide(&filter);
        let mut count: u32 = 0;
        let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
        let ok = unsafe { CredEnumerateW(w.as_ptr(), 0, &mut count, &mut creds) };
        if ok == 0 {
            let e = last_err("CredEnumerate");
            // "No VaultKit entries yet" is an empty list, not an error.
            if e.0 == ERR_NOT_FOUND {
                return Ok(Vec::new());
            }
            return Err(e);
        }
        let mut out = Vec::new();
        unsafe {
            let slice = std::slice::from_raw_parts(creds, count as usize);
            for c in slice {
                let name_ptr = (**c).TargetName;
                if name_ptr.is_null() {
                    continue;
                }
                let mut len = 0;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let name = String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, len));
                if let Some((ns, key)) = parse_target(&name) {
                    out.push(EntryInfo {
                        namespace: ns,
                        key,
                        last_written_unix: filetime_to_unix((**c).LastWritten),
                    });
                }
            }
            CredFree(creds as *mut c_void);
        }
        out.sort_by(|a, b| (&a.namespace, &a.key).cmp(&(&b.namespace, &b.key)));
        Ok(out)
    }
}

#[cfg(windows)]
pub use win::{delete, exists, get, list, put};
