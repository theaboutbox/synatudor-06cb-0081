#ifndef CRYPTBRIDGE_REGISTRY_STATE_H
#define CRYPTBRIDGE_REGISTRY_STATE_H

#include <stdbool.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"

bool cryptbridge_registry_state_active(void);

LSTATUS cryptbridge_registry_state_create_key(
    HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult,
    LPDWORD lpdwDisposition);
LSTATUS cryptbridge_registry_state_open_key(
    HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
LSTATUS cryptbridge_registry_state_set_value(
    HKEY hKey, LPCSTR lpValueName, DWORD dwType,
    const BYTE *lpData, DWORD cbData);
LSTATUS cryptbridge_registry_state_query_value(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpType,
    LPBYTE lpData, LPDWORD lpcbData);
LSTATUS cryptbridge_registry_state_delete_key(HKEY hKey, LPCSTR lpSubKey);
LSTATUS cryptbridge_registry_state_enum_key(
    HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName,
    LPFILETIME lpftLastWriteTime);

#endif
