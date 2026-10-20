//! C ABI surface — everything declared in include/vaultkit.h.
//! Conventions (house standard, from WinRecovery):
//! - String inputs are const char* UTF-8; null is ERR_INVALID_ARG,
//!   except vk_list_json's namespace where null means "all".
//! - `*mut c_char` results are caller-owned; free with `vk_free_string`.
//! - vk_get returns null on failure; use vk_last_error_code() to tell
//!   NOT_FOUND apart from real errors.
//! - Nothing unwinds across the FFI boundary (catch_unwind everywhere).

// The exported functions ARE the raw-pointer C ABI declared in
// include/vaultkit.h; pointer validity is the documented contract there.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::{
    list_json, validate_key, validate_namespace, validate_secret, ERR_INTERNAL, ERR_INVALID_ARG,
    VK_OK,
};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((VK_OK, CString::new("").unwrap()));
}

fn set_error(code: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(clean).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(VK_OK, "");
}

fn guard<T, F: FnOnce() -> T>(f: F) -> std::thread::Result<T> {
    catch_unwind(std::panic::AssertUnwindSafe(f))
}

/// Decode a required UTF-8 input; None (with error set) on null/invalid.
fn input(ptr: *const c_char, what: &str) -> Option<String> {
    if ptr.is_null() {
        set_error(ERR_INVALID_ARG, &format!("{what} must not be null"));
        return None;
    }
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Some(s.to_string()),
        Err(_) => {
            set_error(ERR_INVALID_ARG, &format!("{what} is not valid UTF-8"));
            None
        }
    }
}

fn string_out(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => {
            clear_error();
            c.into_raw()
        }
        Err(_) => {
            set_error(ERR_INTERNAL, "result contained a NUL byte");
            std::ptr::null_mut()
        }
    }
}

fn status(r: crate::VResult<()>) -> c_int {
    match r {
        Ok(()) => {
            clear_error();
            VK_OK
        }
        Err((code, msg)) => {
            set_error(code, &msg);
            code
        }
    }
}

fn validated(ns: *const c_char, key: *const c_char) -> Option<(String, String)> {
    let ns = input(ns, "namespace")?;
    if let Err((c, m)) = validate_namespace(&ns) {
        set_error(c, &m);
        return None;
    }
    let key = input(key, "key")?;
    if let Err((c, m)) = validate_key(&key) {
        set_error(c, &m);
        return None;
    }
    Some((ns, key))
}

#[no_mangle]
pub extern "C" fn vk_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Store (or overwrite) a secret. Returns VK_OK or an ERR_* code.
#[no_mangle]
pub extern "C" fn vk_put(ns: *const c_char, key: *const c_char, secret: *const c_char) -> c_int {
    match guard(|| {
        let Some((ns, key)) = validated(ns, key) else {
            return LAST_ERROR.with(|e| e.borrow().0);
        };
        let Some(secret) = input(secret, "secret") else {
            return ERR_INVALID_ARG;
        };
        if let Err((c, m)) = validate_secret(&secret) {
            set_error(c, &m);
            return c;
        }
        status(crate::platform::put(&ns, &key, &secret))
    }) {
        Ok(code) => code,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            ERR_INTERNAL
        }
    }
}

/// Fetch a secret; null on failure (check vk_last_error_code()).
/// Free the result with vk_free_string.
#[no_mangle]
pub extern "C" fn vk_get(ns: *const c_char, key: *const c_char) -> *mut c_char {
    match guard(|| {
        let Some((ns, key)) = validated(ns, key) else {
            return std::ptr::null_mut();
        };
        match crate::platform::get(&ns, &key) {
            Ok(secret) => string_out(secret),
            Err((c, m)) => {
                set_error(c, &m);
                std::ptr::null_mut()
            }
        }
    }) {
        Ok(p) => p,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            std::ptr::null_mut()
        }
    }
}

/// Delete a secret. Deleting a missing key returns ERR_NOT_FOUND.
#[no_mangle]
pub extern "C" fn vk_delete(ns: *const c_char, key: *const c_char) -> c_int {
    match guard(|| {
        let Some((ns, key)) = validated(ns, key) else {
            return LAST_ERROR.with(|e| e.borrow().0);
        };
        status(crate::platform::delete(&ns, &key))
    }) {
        Ok(code) => code,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            ERR_INTERNAL
        }
    }
}

/// 1 = exists, 0 = does not exist, ERR_* (< 0 impossible; real errors
/// are positive codes distinct from 0/1 — see vk_last_error_code()).
/// Returns -1 on a platform error so 0/1 stay unambiguous.
#[no_mangle]
pub extern "C" fn vk_exists(ns: *const c_char, key: *const c_char) -> c_int {
    match guard(|| {
        let Some((ns, key)) = validated(ns, key) else {
            return -1;
        };
        match crate::platform::exists(&ns, &key) {
            Ok(b) => {
                clear_error();
                if b {
                    1
                } else {
                    0
                }
            }
            Err((c, m)) => {
                set_error(c, &m);
                -1
            }
        }
    }) {
        Ok(v) => v,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            -1
        }
    }
}

/// JSON array of entries: [{"namespace","key","last_written_unix"}].
/// A null namespace lists every VaultKit entry. Metadata only — this
/// never returns secret values.
#[no_mangle]
pub extern "C" fn vk_list_json(ns: *const c_char) -> *mut c_char {
    match guard(|| {
        let ns_owned: Option<String> = if ns.is_null() {
            None
        } else {
            let Some(s) = input(ns, "namespace") else {
                return std::ptr::null_mut();
            };
            if let Err((c, m)) = validate_namespace(&s) {
                set_error(c, &m);
                return std::ptr::null_mut();
            }
            Some(s)
        };
        match crate::platform::list(ns_owned.as_deref()) {
            Ok(entries) => string_out(list_json(&entries)),
            Err((c, m)) => {
                set_error(c, &m);
                std::ptr::null_mut()
            }
        }
    }) {
        Ok(p) => p,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn vk_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = guard(|| unsafe {
            drop(CString::from_raw(ptr));
        });
    }
}

#[no_mangle]
pub extern "C" fn vk_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn vk_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn ffi_contract() {
        assert!(!vk_version().is_null());
        // Null/invalid inputs are clean error codes, never crashes.
        assert_eq!(
            vk_put(ptr::null(), cstr("k").as_ptr(), cstr("v").as_ptr()),
            ERR_INVALID_ARG
        );
        assert_eq!(
            vk_put(
                cstr("bad ns").as_ptr(),
                cstr("k").as_ptr(),
                cstr("v").as_ptr()
            ),
            ERR_INVALID_ARG
        );
        assert_eq!(
            vk_put(cstr("ok").as_ptr(), cstr("k").as_ptr(), ptr::null()),
            ERR_INVALID_ARG
        );
        // Off-Windows the store is NOT_SUPPORTED; on Windows it succeeds,
        // so the storage calls are exercised by the windows integration
        // test instead of here.
        #[cfg(not(windows))]
        {
            assert_eq!(
                vk_put(cstr("ok").as_ptr(), cstr("k").as_ptr(), cstr("v").as_ptr()),
                crate::ERR_NOT_SUPPORTED
            );
            assert!(vk_get(cstr("ok").as_ptr(), cstr("k").as_ptr()).is_null());
            assert_eq!(vk_last_error_code(), crate::ERR_NOT_SUPPORTED);
            assert_eq!(vk_exists(cstr("ok").as_ptr(), cstr("k").as_ptr()), -1);
            assert!(vk_list_json(ptr::null()).is_null());
        }
        vk_free_string(ptr::null_mut()); // no-op, no crash
    }
}
