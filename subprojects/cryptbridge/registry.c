#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "handle.h"
#include "stdlib.h"
#include "stdio.h"


// #define _GNU_SOURCE

/* ---- Win types and error codes (minimal) ---- */
// typedef long LSTATUS;
// typedef uint32_t DWORD;
// typedef unsigned char BYTE;
// typedef BYTE *LPBYTE;
// typedef char *LPSTR;
// typedef const char *LPCSTR;
// typedef DWORD *LPDWORD;
// typedef void *LPSECURITY_ATTRIBUTES;
// typedef void *REGSAM;
// typedef void *HKEY; /* opaque: pointer to a malloc'ed char* path or one of predefined handles */
// typedef HKEY *PHKEY;
// typedef struct { uint32_t dwLowDateTime; uint32_t dwHighDateTime; } FILETIME;
// typedef FILETIME *LPFILETIME;

// #define WINAPI        /* no-op on Linux */

// #define ERROR_SUCCESS           0L
// #define ERROR_FILE_NOT_FOUND    2L
// #define ERROR_ACCESS_DENIED     5L
// #define ERROR_INVALID_PARAMETER 87L
// #define ERROR_MORE_DATA        234L
// #define ERROR_NOT_ENOUGH_MEMORY 8L
// #define ERROR_PATH_NOT_FOUND    3L
// #define ERROR_ALREADY_EXISTS   183L

/* ---- Internal constants ---- */
static char *registry_base_path = NULL;

/* Predefined root keys (paths under base path) */
static char *HKCR_path = NULL; /* HKEY_CLASSES_ROOT */
static char *HKLM_path = NULL; /* HKEY_LOCAL_MACHINE */
static char *HKCU_path = NULL; /* HKEY_CURRENT_USER */
static char *HKU_path  = NULL; /* HKEY_USERS */
static char *HKCC_path = NULL; /* HKEY_CURRENT_CONFIG */

/* Predefined HKEY pointers (unique addresses to compare) */
// static HKEY HKEY_CLASSES_ROOT = (HKEY)0x1001;
// static HKEY HKEY_LOCAL_MACHINE = (HKEY)0x1002;
// static HKEY HKEY_CURRENT_USER = (HKEY)0x1003;
// static HKEY HKEY_USERS = (HKEY)0x1004;
// static HKEY HKEY_CURRENT_CONFIG = (HKEY)0x1005;

/* Default value filename when lpValueName == NULL or empty */
static const char *DEFAULT_VALUE_NAME = ".default";

/* Utility prototypes */
static const char *get_base_path(void);
static void ensure_base_and_roots(void);
static char *join_path(const char *a, const char *b);
static int make_dirs_recursive(const char *path);
static int is_dir(const char *path);
static int is_file(const char *path);
static char *normalize_keyname(const char *subkey);
static char *hkey_to_path(HKEY hKey);
static char *canonicalize_value_name(const char *valname);
static int remove_dir_recursive(const char *path);

/* ---- Implementations ---- */

static const char *get_base_path(void)
{
    if (registry_base_path) return registry_base_path;
    // const char *home = getenv("HOME");
    // if (home && home[0])
    // {
    //     size_t n = strlen(home) + strlen("/.local/share/regemu") + 1;
    //     registry_base_path = malloc(n);
    //     if (!registry_base_path) return NULL;
    //     snprintf(registry_base_path, n, "%s/.local/share/regemu", home);
    // }
    // else
    // {
    //     registry_base_path = strdup("/tmp/regemu");
    // }

    registry_base_path = strdup("/tmp/synatudor-registry");
    return registry_base_path;
}

/* Ensure base path and root key subdirs exist and create cached root paths */
static void ensure_base_and_roots(void)
{
    if (HKCR_path) return; /* initialized */

    const char *base = get_base_path();
    if (!base) return;

    /* create base dir */
    make_dirs_recursive(base);

    /* allocate root paths */
    size_t base_len = strlen(base);
    #define MAKE_ROOT(name,path_suffix,var) do { \
        size_t needed = base_len + 1 + strlen(path_suffix) + 1; \
        var = malloc(needed); \
        if(var) snprintf(var, needed, "%s/%s", base, path_suffix); \
        make_dirs_recursive(var); \
    } while(0)

    MAKE_ROOT("HKCR","HKCR", HKCR_path);
    MAKE_ROOT("HKLM","HKLM", HKLM_path);
    MAKE_ROOT("HKCU","HKCU", HKCU_path);
    MAKE_ROOT("HKU","HKU", HKU_path);
    MAKE_ROOT("HKCC","HKCC", HKCC_path);

    #undef MAKE_ROOT
}

/* Join two path components with '/' (allocates new string) */
static char *join_path(const char *a, const char *b)
{
    if (!a) a = "";
    if (!b) b = "";
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int need_sep = (la > 0 && a[la-1] != '/');
    size_t n = la + (need_sep ? 1 : 0) + lb + 1;
    char *res = malloc(n);
    if (!res) return NULL;
    if (need_sep) snprintf(res, n, "%s/%s", a, b);
    else snprintf(res, n, "%s%s", a, b);
    return res;
}

/* Create directories recursively (like mkdir -p). Returns 0 on success, -1 on failure */
static int make_dirs_recursive(const char *path)
{
    printf("Running as: UID=%d, EUID=%d, GID=%d, EGID=%d\n", 
           getuid(), geteuid(), getgid(), getegid());

    if (!path || path[0] == '\0') return -1;
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    lstrcpynA(tmp, path, sizeof(tmp));
    tmp[len] = '\0';

    /* If path already exists and is a directory, done */
    struct stat st;
    if (stat(tmp, &st) == 0)
    {
        if (S_ISDIR(st.st_mode)) return 0;
        /* exists but not a dir: fail */
        return -1;
    }

    /* iterate and create */
    for (char *p = tmp + 1; *p; ++p)
    {
        if (*p == '/')
        {
            *p = '\0';
            printf("Creating: '%s'\n", tmp);
            
            int ret = mkdir(tmp, 0755);
            int err = errno;
            
            printf("mkdir returned %d, errno=%d\n", ret, err);
            
            if (ret != 0 && err != EEXIST)
            {
                printf("Error mkdir %s: %d (%s)\n", tmp, err, strerror(err));
                return -1;
            }
            
            *p = '/';


        }
    }
    /* final */
    if (mkdir(tmp, 0755) != 0)
    {
        printf("Error mkdir final: %d\n", errno);
        if (errno != EEXIST) return -1;
    }
    return 0;
}

static int is_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int is_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

/* Normalize key name: replace backslashes with slashes and remove leading/trailing slashes.
   Returns malloc'ed string. */
static char *normalize_keyname(const char *subkey)
{
    if (!subkey) return NULL;
    const char *in = subkey;
    size_t L = strlen(in);
    char *out = malloc(L + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < L; ++i)
    {
        char c = in[i];
        if (c == '\\') c = '/';
        if (j == 0 && c == '/') continue; /* skip leading */
        out[j++] = c;
    }
    /* remove trailing slash if any */
    while (j > 0 && out[j-1] == '/') --j;
    out[j] = '\0';
    return out;
}

/* Map an HKEY handle (our opaque value) to an absolute path string.
   Returns a malloc'ed string (caller must free) or NULL on error.
   If hKey is one of the predefined constants, returns its cached path strdup.
   Otherwise expects hKey is a char* pointer (malloc'ed string) representing the path. */
static char *hkey_to_path(HKEY hKey)
{
    ensure_base_and_roots();
    if (!hKey) return NULL;

    if (hKey == HKEY_CLASSES_ROOT) return strdup(HKCR_path);
    if (hKey == HKEY_LOCAL_MACHINE) return strdup(HKLM_path);
    if (hKey == HKEY_CURRENT_USER) return strdup(HKCU_path);
    if (hKey == HKEY_USERS) return strdup(HKU_path);
    if (hKey == HKEY_CURRENT_CONFIG) return strdup(HKCC_path);

    /* Otherwise we expect hKey is a pointer to a malloc'd char* path */
    char *p = (char *)hKey;
    /* protect: ensure p is a plausible path string */
    if (p[0] == '\0') return NULL;
    return strdup(p);
}

/* Convert a possibly-NULL value name to the filename used on disk. */
static char *canonicalize_value_name(const char *valname)
{
    if (!valname || valname[0] == '\0') return strdup(DEFAULT_VALUE_NAME);
    /* Replace characters that would confuse paths (slash/backslash) */
    size_t L = strlen(valname);
    char *out = malloc(L + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < L; ++i)
    {
        char c = valname[i];
        if (c == '/' || c == '\\') c = '_';
        out[i] = c;
    }
    out[L] = '\0';
    return out;
}

/* Remove directory recursively (files and subdirs). Returns 0 on success, -1 on failure. */
static int remove_dir_recursive(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
    {
        if (errno == ENOENT) return 0; /* not present => success */
        return -1;
    }
    struct dirent *entry;
    char child[PATH_MAX];
    int ret = 0;
    while ((entry = readdir(d)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(child, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                if (remove_dir_recursive(child) != 0) ret = -1;
            }
            else
            {
                if (unlink(child) != 0) ret = -1;
            }
        }
    }
    closedir(d);
    if (rmdir(path) != 0) ret = -1;
    return ret;
}

/* ----------------- Exported functions ----------------- */

/* RegCreateKeyExA:
 * Creates or opens a key. If phkResult != NULL, returns a new HKEY (malloc'ed string)
 * representing the full path to the key; caller should call RegCloseKey on it.
 *
 * We ignore parameters: dwOptions, samDesired, SECURITY_ATTRIBUTES, lpdwDisposition mostly.
 */
LSTATUS WINAPI RegCreateKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition)
{
    if (!hKey || !lpSubKey) return ERROR_INVALID_PARAMETER;
    char *parent = hkey_to_path(hKey);
    if (!parent) return ERROR_INVALID_PARAMETER;

    char *subnorm = normalize_keyname(lpSubKey);
    if (!subnorm) { free(parent); return ERROR_NOT_ENOUGH_MEMORY; }

    char *full = join_path(parent, subnorm);
    free(parent);
    free(subnorm);
    if (!full) return ERROR_NOT_ENOUGH_MEMORY;

    printf("make_dirs: %s\n", full);
    if (make_dirs_recursive(full) != 0)
    {
        free(full);
        return ERROR_ACCESS_DENIED;
    }

    if (phkResult)
    {
        /* phkResult receives a malloc'ed string pointer cast to HKEY */
        char *h = strdup(full);
        if (!h) { free(full); return ERROR_NOT_ENOUGH_MEMORY; }
        *phkResult = (HKEY)h;
    }
    if (lpdwDisposition) *lpdwDisposition = 0; /* not distinguishing new/opened */
    free(full);
    return ERROR_SUCCESS;
}

/* RegOpenKeyExA:
 * Opens an existing key. Does not create it. On success returns a new HKEY (malloc'ed).
 */
LSTATUS WINAPI RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult)
{
    if (!hKey || !lpSubKey || !phkResult) return ERROR_INVALID_PARAMETER;
    char *parent = hkey_to_path(hKey);
    if (!parent) return ERROR_INVALID_PARAMETER;

    char *subnorm = normalize_keyname(lpSubKey);
    if (!subnorm) { free(parent); return ERROR_NOT_ENOUGH_MEMORY; }

    char *full = join_path(parent, subnorm);
    printf("RegOpenKeyExA: %s\n", full);
    free(parent);
    free(subnorm);
    if (!full) return ERROR_NOT_ENOUGH_MEMORY;

    if (!is_dir(full))
    {
        free(full);
        return ERROR_FILE_NOT_FOUND;
    }

    char *h = strdup(full);
    if (!h) { free(full); return ERROR_NOT_ENOUGH_MEMORY; }
    *phkResult = (HKEY)h;
    free(full);
    return ERROR_SUCCESS;
}

/* RegCloseKey:
 * Frees an HKEY obtained from RegCreateKeyExA / RegOpenKeyExA.
 * Predefined handles are no-ops.
 */
LSTATUS WINAPI RegCloseKey(HKEY hKey)
{
    if (!hKey) return ERROR_INVALID_PARAMETER;
    if (hKey == HKEY_CLASSES_ROOT || hKey == HKEY_LOCAL_MACHINE ||
        hKey == HKEY_CURRENT_USER || hKey == HKEY_USERS ||
        hKey == HKEY_CURRENT_CONFIG)
    {
        /* predefined roots: nothing to free */
        return ERROR_SUCCESS;
    }
    /* we expect hKey is a malloc'ed path string */
    char *p = (char *)hKey;
    free(p);
    return ERROR_SUCCESS;
}

/* RegSetValueExA:
 * Writes lpData (cbData bytes) to a value file under the key directory.
 * If lpValueName is NULL/empty, uses the default value filename.
 */
LSTATUS WINAPI RegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData)
{
    printf("RegSetValueExA: %s\n", lpValueName);
    printf("lpdata = %p cbdata = %d\n", lpData, cbData);
    if (!hKey || !lpValueName) {
        /* Allow NULL to signal default name - follow convention: NULL treated as default */
        /* but require a valid key handle: */
    }
    char *keypath = hkey_to_path(hKey);
    if (!keypath) return ERROR_INVALID_PARAMETER;

    /* value filename */
    char *fname = canonicalize_value_name(lpValueName);
    if (!fname) { free(keypath); return ERROR_NOT_ENOUGH_MEMORY; }

    char *full = join_path(keypath, fname);
    free(keypath);
    free(fname);
    if (!full) return ERROR_NOT_ENOUGH_MEMORY;

    /* make sure key directory exists */
    char *dirc = strdup(full);
    if (!dirc) { free(full); return ERROR_NOT_ENOUGH_MEMORY; }
    for (char *p = dirc + strlen(dirc) - 1; p >= dirc; --p)
    {
        if (*p == '/') { *p = '\0'; break; }
    }
    int mkres = make_dirs_recursive(dirc);
    free(dirc);
    if (mkres != 0) { free(full); return ERROR_PATH_NOT_FOUND; }

    /* write file (binary) */
    int fd = open(full, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { free(full); return ERROR_ACCESS_DENIED; }
    ssize_t wrote = 0;
    if (cbData > 0 && lpData)
    {
        ssize_t w = write(fd, lpData, cbData);
        if (w < 0) { close(fd); free(full); return ERROR_ACCESS_DENIED; }
        wrote = w;
    }
    close(fd);
    free(full);
    (void)Reserved; (void)dwType; /* no-op for type in this simple emulator */
    return ERROR_SUCCESS;
}

/* RegQueryValueExA:
 * Read a named value. If lpData==NULL, set *lpcbData to required size.
 * If *lpcbData < required size, copy as much as fits and return ERROR_MORE_DATA.
 *
 * Note: Parameter ordering follows standard:
 *   RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
 * In the user's earlier listings the third parameter looked like LPDWORD reserved and
 * fourth like LPDWORD type: we implement according to Win32 signature.
 */
LSTATUS WINAPI RegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved, /* typically NULL; ignored */
    LPDWORD lpType,     /* out: type; here we set to 1 (REG_BINARY) */
    LPBYTE lpData,
    LPDWORD lpcbData)
{
    (void)lpReserved;
    if (!hKey) return ERROR_INVALID_PARAMETER;
    if (!lpcbData) return ERROR_INVALID_PARAMETER;

    char *keypath = hkey_to_path(hKey);
    if (!keypath) return ERROR_INVALID_PARAMETER;

    char *fname = canonicalize_value_name(lpValueName);
    if (!fname) { free(keypath); return ERROR_NOT_ENOUGH_MEMORY; }

    char *full = join_path(keypath, fname);
    free(keypath);
    free(fname);
    if (!full) return ERROR_NOT_ENOUGH_MEMORY;

    if (!is_file(full))
    {
        free(full);
        return ERROR_FILE_NOT_FOUND;
    }

    /* open and get size */
    struct stat st;
    if (stat(full, &st) != 0) { free(full); return ERROR_ACCESS_DENIED; }
    size_t needed = (size_t)st.st_size;
    if (lpType) *lpType = 1; /* treat as REG_BINARY in this minimal emulation */

    if (lpData == NULL)
    {
        *lpcbData = (DWORD)needed;
        free(full);
        return ERROR_SUCCESS;
    }

    if (*lpcbData < (DWORD)needed)
    {
        /* partial read allowed, return ERROR_MORE_DATA after copying as much as possible */
        FILE *f = fopen(full, "rb");
        if (!f) { free(full); return ERROR_ACCESS_DENIED; }
        size_t toread = *lpcbData;
        size_t r = fread(lpData, 1, toread, f);
        fclose(f);
        *lpcbData = (DWORD)r;
        free(full);
        return ERROR_MORE_DATA;
    }
    /* buffer large enough */
    FILE *f = fopen(full, "rb");
    if (!f) { free(full); return ERROR_ACCESS_DENIED; }
    size_t r = fread(lpData, 1, needed, f);
    fclose(f);
    *lpcbData = (DWORD)r;
    free(full);
    return ERROR_SUCCESS;
}

/* RegDeleteKeyA:
 * Delete a subkey under hKey. We perform recursive delete of the directory and contents.
 */
LSTATUS WINAPI RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
{
    if (!hKey || !lpSubKey) return ERROR_INVALID_PARAMETER;
    char *parent = hkey_to_path(hKey);
    if (!parent) return ERROR_INVALID_PARAMETER;

    char *subnorm = normalize_keyname(lpSubKey);
    if (!subnorm) { free(parent); return ERROR_NOT_ENOUGH_MEMORY; }

    char *full = join_path(parent, subnorm);
    free(parent);
    free(subnorm);
    if (!full) return ERROR_NOT_ENOUGH_MEMORY;

    if (!is_dir(full))
    {
        free(full);
        return ERROR_FILE_NOT_FOUND;
    }

    if (remove_dir_recursive(full) != 0)
    {
        free(full);
        return ERROR_ACCESS_DENIED;
    }

    free(full);
    return ERROR_SUCCESS;
}

/* RegEnumKeyExA:
 * Enumerate subkeys (directories) of the key. dwIndex is zero-based.
 * Returns ERROR_SUCCESS and fills lpName (and *lpcName) if found.
 * If buffer too small, return ERROR_MORE_DATA and set *lpcName to needed size.
 * Ignored: lpReserved, lpClass, lpdwClassLen, lpftLastWriteTime (we set zero).
 */
LSTATUS WINAPI RegEnumKeyExA(
    HKEY hKey,
    DWORD dwIndex,
    LPSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPSTR lpClass,
    LPDWORD lpdwClassLen,
    LPFILETIME lpftLastWriteTime)
{
    (void)lpReserved; (void)lpClass; (void)lpdwClassLen;
    if (!hKey) return ERROR_INVALID_PARAMETER;
    if (!lpcName) return ERROR_INVALID_PARAMETER;

    char *keypath = hkey_to_path(hKey);
    if (!keypath) return ERROR_INVALID_PARAMETER;

    DIR *d = opendir(keypath);
    if (!d) { free(keypath); return ERROR_ACCESS_DENIED; }

    struct dirent *ent;
    DWORD idx = 0;
    LSTATUS ret = ERROR_FILE_NOT_FOUND;
    while ((ent = readdir(d)) != NULL)
    {
        /* skip files (values), only consider directories */
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char candidate_path[PATH_MAX];
        snprintf(candidate_path, sizeof(candidate_path), "%s/%s", keypath, ent->d_name);
        if (!is_dir(candidate_path)) continue;
        if (idx == dwIndex)
        {
            size_t needed = strlen(ent->d_name) + 1;
            if (lpName == NULL || *lpcName < (DWORD)needed)
            {
                *lpcName = (DWORD)needed;
                ret = ERROR_MORE_DATA;
            }
            else
            {
                lstrcpynA(lpName, ent->d_name, *lpcName);
                lpName[*lpcName - 1] = '\0'; /* ensure NUL */
                *lpcName = (DWORD)strlen(lpName);
                ret = ERROR_SUCCESS;
            }
            /* set last write time if requested (zeroed for simplicity) */
            if (lpftLastWriteTime)
            {
                lpftLastWriteTime->dwLowDateTime = 0;
                lpftLastWriteTime->dwHighDateTime = 0;
            }
            break;
        }
        ++idx;
    }
    closedir(d);
    free(keypath);
    return ret;
}

/* ----------------- End of registry emulation ----------------- */

/* For convenience: initialization on load (optional) */
__attribute__((constructor))
static void registry_init(void)
{
    ensure_base_and_roots();
}

/* Optional debug/test main (comment out when integrating) */
#ifdef REGEMU_TEST
int main(void)
{
    printf("Base registry path: %s\n", get_base_path());
    HKEY hk;
    LSTATUS s = RegCreateKeyExA(HKEY_CURRENT_USER, "Software/MyApp/Settings", 0, NULL, 0, NULL, NULL, &hk, NULL);
    printf("RegCreateKeyExA => %ld\n", s);
    const char *data = "hello!";
    s = RegSetValueExA(hk, "Greeting", 0, 1, (const BYTE*)data, (DWORD)strlen(data));
    printf("RegSetValueExA => %ld\n", s);
    DWORD sz = 0;
    s = RegQueryValueExA(hk, "Greeting", NULL, NULL, NULL, &sz);
    printf("RegQueryValueExA size => %ld, sz=%u\n", s, (unsigned)sz);
    char buf[100];
    sz = sizeof(buf);
    s = RegQueryValueExA(hk, "Greeting", NULL, NULL, (LPBYTE)buf, &sz);
    printf("RegQueryValueExA read => %ld, got %u bytes: '%.*s'\n", s, (unsigned)sz, (int)sz, buf);
    RegCloseKey(hk);
    return 0;
}
#endif
