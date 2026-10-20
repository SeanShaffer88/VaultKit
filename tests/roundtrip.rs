//! Windows-only end-to-end proof: real DPAPI + Credential Manager
//! roundtrip through the public C ABI. Runs natively on Windows CI;
//! compiles to nothing elsewhere.

#![cfg(windows)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use vaultkit::ffi::*;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn take(ptr: *mut c_char) -> String {
    assert!(
        !ptr.is_null(),
        "null result; last error: {:?}",
        unsafe { CStr::from_ptr(vk_last_error()) }.to_string_lossy()
    );
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
    vk_free_string(ptr);
    s
}

#[test]
fn dpapi_credman_roundtrip() {
    // Unique namespace per run so parallel CI jobs never collide, and
    // cleanup always happens via the delete at the end.
    let ns = format!("vk-test-{}", std::process::id());
    let ns = cs(&ns);
    let key = cs("api-token");
    let secret = "s3cr3t-value/with+symbols=✓";

    {
        assert_eq!(vk_exists(ns.as_ptr(), key.as_ptr()), 0);
        assert_eq!(
            vk_put(ns.as_ptr(), key.as_ptr(), cs(secret).as_ptr()),
            VK_OK_I32
        );
        assert_eq!(vk_exists(ns.as_ptr(), key.as_ptr()), 1);
        assert_eq!(take(vk_get(ns.as_ptr(), key.as_ptr())), secret);

        // Overwrite wins.
        assert_eq!(
            vk_put(ns.as_ptr(), key.as_ptr(), cs("second").as_ptr()),
            VK_OK_I32
        );
        assert_eq!(take(vk_get(ns.as_ptr(), key.as_ptr())), "second");

        // Listing shows metadata (never the secret).
        let json = take(vk_list_json(ns.as_ptr()));
        assert!(json.contains("api-token"), "list json: {json}");
        assert!(!json.contains("second"), "list must not leak secrets");

        // Delete, then reads report NOT_FOUND precisely.
        assert_eq!(vk_delete(ns.as_ptr(), key.as_ptr()), VK_OK_I32);
        assert_eq!(vk_exists(ns.as_ptr(), key.as_ptr()), 0);
        assert!(vk_get(ns.as_ptr(), key.as_ptr()).is_null());
        assert_eq!(vk_last_error_code(), 3); // ERR_NOT_FOUND
        assert_eq!(vk_delete(ns.as_ptr(), key.as_ptr()), 3);
    }
}

const VK_OK_I32: i32 = 0;
