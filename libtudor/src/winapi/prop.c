#include "internal.h"

// typedef struct _PROPVARIANT PROPVARIANT;
// typedef struct _PROPVARIANT {
//     USHORT vt;
//     BYTE wReserved1;
//     BYTE wReserved2;
//     ULONG wReserved3;
//     union {
//         CHAR cVal;
//         UCHAR bVal;
//         SHORT iVal;
//         USHORT uiVal;
//         LONG lVal;
//         ULONG ulVal;
//         INT intVal;
//         UINT uintVal;
//         CHAR *pcVal;
//         UCHAR *pbVal;
//         SHORT *piVal;
//         USHORT *puiVal;
//         LONG *plVal;
//         ULONG *pulVal;
//         INT *pintVal;
//         UINT *puintVal;
//         PROPVARIANT *pvarVal;
//     };
// } PROPVARIANT;

typedef enum _VARENUM {
  VT_EMPTY = 0,
  VT_NULL = 1,
  VT_I2 = 2,
  VT_I4 = 3,
  VT_R4 = 4,
  VT_R8 = 5,
  VT_CY = 6,
  VT_DATE = 7,
  VT_BSTR = 8,
  VT_DISPATCH = 9,
  VT_ERROR = 10,
  VT_BOOL = 11,
  VT_VARIANT = 12,
  VT_UNKNOWN = 13,
  VT_DECIMAL = 14,
  VT_I1 = 16,
  VT_UI1 = 17,
  VT_UI2 = 18,
  VT_UI4 = 19,
  VT_I8 = 20,
  VT_UI8 = 21,
  VT_INT = 22,
  VT_UINT = 23,
  VT_VOID = 24,
  VT_HRESULT = 25,
  VT_PTR = 26,
  VT_SAFEARRAY = 27,
  VT_CARRAY = 28,
  VT_USERDEFINED = 29,
  VT_LPSTR = 30,
  VT_LPWSTR = 31,
  VT_RECORD = 36,
  VT_INT_PTR = 37,
  VT_UINT_PTR = 38,
  VT_FILETIME = 64,
  VT_BLOB = 65,
  VT_STREAM = 66,
  VT_STORAGE = 67,
  VT_STREAMED_OBJECT = 68,
  VT_STORED_OBJECT = 69,
  VT_BLOB_OBJECT = 70,
  VT_CF = 71,
  VT_CLSID = 72,
  VT_VERSIONED_STREAM = 73,
  VT_BSTR_BLOB = 0xfff,
  VT_VECTOR = 0x1000,
  VT_ARRAY = 0x2000,
  VT_BYREF = 0x4000,
  VT_RESERVED = 0x8000,
  VT_ILLEGAL = 0xffff,
  VT_ILLEGALMASKED = 0xfff,
  VT_TYPEMASK = 0xfff
} VARENUM;

// typedef struct _PROPVARIANT PROPVARIANT;
typedef struct _BLOB {
  ULONG cbSize;
  BYTE  *pBlobData;
} BLOB, *LPBLOB;


typedef struct tagDEC {
  USHORT wReserved;
  union {
    struct {
      BYTE scale;
      BYTE sign;
    } DUMMYSTRUCTNAME;
    USHORT signscale;
  } DUMMYUNIONNAME;
  ULONG  Hi32;
  union {
    struct {
      ULONG Lo32;
      ULONG Mid32;
    } DUMMYSTRUCTNAME2;
    ULONGLONG Lo64;
  } DUMMYUNIONNAME2;
} DECIMAL;

// struct PROPVARIANT;

typedef struct PROPVARIANT {
    uint16_t vt;
    uint16_t wReserved1;
    uint16_t wReserved2;
    uint16_t wReserved3;
    union {
        CHAR cVal;
        UCHAR bVal;
        SHORT iVal;
        USHORT uiVal;
        LONG lVal;
        ULONG ulVal;
        INT intVal;
        UINT uintVal;
        CHAR *pcVal;
        UCHAR *pbVal;
        SHORT *piVal;
        USHORT *puiVal;
        LONG *plVal;
        ULONG *pulVal;
        INT *pintVal;
        UINT *puintVal;
        struct PROPVARIANT *pvarVal;
        BLOB              blob;
    };
    DECIMAL decVal;
} PROPVARIANT;


__winfnc HRESULT PropVariantClear(PROPVARIANT *pvar) {
    TRACE();
    // *pvar = (PROPVARIANT) {0};
    memset(pvar, 0, sizeof(PROPVARIANT));
    return ERROR_SUCCESS;
}
WINAPI(PropVariantClear)
