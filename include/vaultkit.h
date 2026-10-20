/* VaultKit.dll — secrets storage for Windows apps, without the pain.
 *
 * Each secret is a Windows generic credential named
 * "VaultKit/<namespace>/<key>", whose blob is additionally
 * DPAPI-protected (CurrentUser) with the target name as entropy.
 *
 * Strings are UTF-8, NUL-terminated. Returned char* are caller-owned:
 * free them with vk_free_string(). Failures set a thread-local error;
 * read it with vk_last_error() / vk_last_error_code().
 *
 * Limits: namespace <= 64 chars [A-Za-z0-9._-]; key <= 128 chars (no
 * '/', '\\', '*', '?'); secret <= 2000 bytes. */
#ifndef VAULTKIT_H
#define VAULTKIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(VK_BUILD)
#define VK_API __declspec(dllexport)
#elif defined(_WIN32)
#define VK_API __declspec(dllimport)
#else
#define VK_API
#endif

enum {
    VK_OK = 0,
    VK_ERR_INVALID_ARG = 1,
    VK_ERR_NOT_SUPPORTED = 2,
    VK_ERR_NOT_FOUND = 3,
    VK_ERR_ACCESS_DENIED = 4,
    VK_ERR_PLATFORM = 5,
    VK_ERR_INTERNAL = 6
};

/* "0.1.0" — static string, do not free. */
VK_API const char *vk_version(void);

/* Store or overwrite a secret. Returns VK_OK or an error code. */
VK_API int vk_put(const char *namespace_, const char *key, const char *secret);

/* Fetch a secret, or NULL on failure (VK_ERR_NOT_FOUND when absent). */
VK_API char *vk_get(const char *namespace_, const char *key);

/* Delete a secret; VK_ERR_NOT_FOUND when absent. */
VK_API int vk_delete(const char *namespace_, const char *key);

/* 1 = exists, 0 = does not exist, -1 = platform error. */
VK_API int vk_exists(const char *namespace_, const char *key);

/* JSON array of {"namespace","key","last_written_unix"} for one
 * namespace, or every VaultKit entry when namespace_ is NULL.
 * Metadata only — never returns secret values. */
VK_API char *vk_list_json(const char *namespace_);

VK_API void vk_free_string(char *ptr);
VK_API const char *vk_last_error(void);
VK_API int vk_last_error_code(void);

#ifdef __cplusplus
}
#endif
#endif /* VAULTKIT_H */
