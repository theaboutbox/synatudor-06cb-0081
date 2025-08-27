#ifndef WUDF1_MINIMAL_CPP_H
#define WUDF1_MINIMAL_CPP_H

#include "internal.h"
#include <iostream>
#include <string>
#include <cstdint>

#define _In_opt_ 
#define _In_ 
#define _Out_ 
#define _Out_opt_
#define _Inout_
#define _Out_writes_to_opt_
#define __drv_aliasesMem


/* ----------------- Basic COM / Win32 types ------------------ */
// typedef int32_t  HRESULT;
// typedef uint32_t ULONG;
// typedef int      BOOL;
// #define TRUE  1
// #define FALSE 0

// struct GUID {
//     uint32_t Data1;
//     uint16_t Data2;
//     uint16_t Data3;
//     uint8_t  Data4[8];
// };

typedef const GUID_DLL* REFGUID;
typedef const GUID_DLL* REFIID;
typedef const GUID_DLL* LPCGUID;
//
// #if defined(_WIN32) || defined(__CYGWIN__)
// # define STDAPICALLTYPE __stdcall
// #else
// # define STDAPICALLTYPE
// #endif

typedef const char16_t* PCWSTR;
typedef const char16_t* LPCWSTR;
typedef wchar_t* LPWSTR;
typedef wchar_t* PWSTR;
typedef void* LPVOID;
typedef wchar_t* LPOLESTR;

#define __winfnc __attribute__((ms_abi))

# define STDAPICALLTYPE __winfnc
# define STDMETHODCALLTYPE __winfnc

/* COM HRESULT macros */
#ifndef SUCCEEDED
# define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#endif
#ifndef FAILED
# define FAILED(hr) (((HRESULT)(hr)) < 0)
#endif

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

#define DECIMAL_SETZERO(d)   \
    do {                     \
        (d).wReserved = 0;   \
        (d).Hi32 = 0;        \
        (d).DUMMYUNIONNAME2.Lo64 = 0; \
        (d).DUMMYUNIONNAME.signscale = 0; \
    } while (0)

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

typedef struct _PROPVARIANT PROPVARIANT;
typedef struct _PROPVARIANT {
    USHORT vt;
    BYTE wReserved1;
    BYTE wReserved2;
    ULONG wReserved3;
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
        PROPVARIANT *pvarVal;
        BLOB              blob;
    };
    DECIMAL decVal;
} PROPVARIANT;


typedef enum _WDF_TRI_STATE {
    WdfUseDefault   = 0,
    WdfFalse        = 1,
    WdfTrue         = 2,
} WDF_TRI_STATE, *PWDF_TRI_STATE;

typedef enum _WDF_CALLBACK_CONSTRAINT
{
    None                = 0,
    WdfDeviceLevel      = 1,
    WdfLevelReserved    = 2,
    WdfLevelMaximum
}WDF_CALLBACK_CONSTRAINT;

typedef enum _WDF_IO_QUEUE_DISPATCH_TYPE
{
  WdfIoQueueDispatchSequential = 1,
  WdfIoQueueDispatchParallel   = 2,
  WdfIoQueueDispatchManual     = 3,
  WdfIoQueueDispatchMaximum
} WDF_IO_QUEUE_DISPATCH_TYPE;

typedef enum _WDF_IO_QUEUE_STATE
{
    WdfIoQueueAcceptRequests    = 0x01,
    WdfIoQueueDispatchRequests  = 0x02,
    WdfIoQueueNoRequests        = 0x04,
    WdfIoQueueDriverNoRequests  = 0x08,
    WdfIoQueuePnpHeld           = 0x10
} WDF_IO_QUEUE_STATE, *PWDF_IO_QUEUE_STATE;

typedef enum _WDF_EVENT_TYPE {
  WdfEventReserved = 0,
  WdfEventBroadcast = 1,
  WdfEventMaximum
} WDF_EVENT_TYPE;

typedef enum _WDF_PNP_STATE {
  WdfPnpStateInvalid,
  WdfPnpStateDisabled,
  WdfPnpStateFailed,
  WdfPnpStateRemoved,
  WdfPnpStateResourcesChanged,
  WdfPnpStateDontDisplayInUI,
  WdfPnpStateNotDisableable,
  WdfPnpStateMaximum
} WDF_PNP_STATE;

typedef enum _WDF_POWER_POLICY_S0_IDLE_CAPABILITIES {
  IdleCapsInvalid = 0,
  IdleCannotWakeFromS0,
  IdleCanWakeFromS0,
  IdleUsbSelectiveSuspend
} WDF_POWER_POLICY_S0_IDLE_CAPABILITIES;

typedef enum _DEVICE_POWER_STATE {
  PowerDeviceUnspecified,
  PowerDeviceD0,
  PowerDeviceD1,
  PowerDeviceD2,
  PowerDeviceD3,
  PowerDeviceMaximum
} DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

typedef enum _WDF_POWER_POLICY_S0_IDLE_USER_CONTROL {
  IdleUserControlInvalid = 0,
  IdleDoNotAllowUserControl,
  IdleAllowUserControl
} WDF_POWER_POLICY_S0_IDLE_USER_CONTROL;

typedef enum _WDF_DEVICE_IO_TYPE {
  WdfDeviceIoUndefined = 0,
  WdfDeviceIoNeither,
  WdfDeviceIoBuffered,
  WdfDeviceIoDirect,
  WdfDeviceIoBufferedOrDirect = 4,
  WdfDeviceIoMaximum
} WDF_DEVICE_IO_TYPE, *PWDF_DEVICE_IO_TYPE;

typedef enum _WDF_POWER_POLICY_SX_WAKE_USER_CONTROL {
  WakeUserControlInvalid = 0,
  WakeDoNotAllowUserControl,
  WakeAllowUserControl
} WDF_POWER_POLICY_SX_WAKE_USER_CONTROL;

typedef enum {
  PowerActionNone = 0,
  PowerActionReserved,
  PowerActionSleep,
  PowerActionHibernate,
  PowerActionShutdown,
  PowerActionShutdownReset,
  PowerActionShutdownOff,
  PowerActionWarmEject,
  PowerActionDisplayOff
} POWER_ACTION, *PPOWER_ACTION;


typedef enum _WDF_PROPERTY_STORE_DISPOSITION {
  CreatedNewStore,
  OpenedExistingStore
} WDF_PROPERTY_STORE_DISPOSITION;

typedef enum _WDF_PNP_CAPABILITY {
  WdfPnpCapInvalid,
  WdfPnpCapLockSupported,
  WdfPnpCapEjectSupported,
  WdfPnpCapRemovable,
  WdfPnpCapDockDevice,
  WdfPnpCapSurpriseRemovalOk,
  WdfPnpCapNoDisplayInUI,
  WdfPnpCapMaximum
} WDF_PNP_CAPABILITY;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef enum _MEMORY_CACHING_TYPE {
  MmNonCached,
  MmCached,
  MmWriteCombined,
  MmHardwareCoherentCached,
  MmNonCachedUnordered,
  MmUSWCCached,
  MmMaximumCacheType,
  MmNotMapped
} MEMORY_CACHING_TYPE;

typedef enum _WDF_DEVICE_HWACCESS_TARGET_TYPE {
  WdfDeviceHwAccessTargetTypeInvalid = 0,
  WdfDeviceHwAccessTargetTypeRegister,
  WdfDeviceHwAccessTargetTypeRegisterBuffer,
  WdfDeviceHwAccessTargetTypePort,
  WdfDeviceHwAccessTargetTypePortBuffer,
  WdfDeviceHwAccessTargetTypeMaximum
} WDF_DEVICE_HWACCESS_TARGET_TYPE, *PWDF_DEVICE_HWACCESS_TARGET_TYPE;

typedef enum _WDF_DEVICE_HWACCESS_TARGET_SIZE {
  WdfDeviceHwAccessTargetSizeInvalid = 0,
  WdfDeviceHwAccessTargetSizeUchar,
  WdfDeviceHwAccessTargetSizeUshort,
  WdfDeviceHwAccessTargetSizeUlong,
  WdfDeviceHwAccessTargetSizeUlong64,
  WdfDeviceHwAccessTargetSizeMaximum
} WDF_DEVICE_HWACCESS_TARGET_SIZE, *PWDF_DEVICE_HWACCESS_TARGET_SIZE;


typedef struct _WUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS {
  ULONG                                 Size;
  WDF_POWER_POLICY_S0_IDLE_CAPABILITIES IdleCaps;
  DEVICE_POWER_STATE                    DxState;
  ULONG                                 IdleTimeout;
  WDF_POWER_POLICY_S0_IDLE_USER_CONTROL UserControlOfIdleSettings;
  WDF_TRI_STATE                         Enabled;
  WDF_TRI_STATE                         PowerUpIdleDeviceOnSystemWake;
  WDF_TRI_STATE                         ExcludeD3Cold;
} WUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS, *PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS;


// typedef enum _WDF_REQUEST_TYPE
// {
//     WdfRequestUndefined        = 0,
//     WdfRequestCreate           = 1,
//     WdfRequestCleanup          = 2,
//     WdfRequestRead             = 3,
//     WdfRequestWrite            = 4,
//     WdfRequestDeviceIoControl  = 5,
//     WdfRequestClose            = 6,
//     WdfRequestUsb              = 7,
//     WdfRequestOther            = 8,
//     WdfRequestInternalIoctl    = 9,
//     WdfRequestTypeNoFormat     = 10,
//     WdfRequestFlushBuffers     = 11,
//     WdfRequestQueryInformation = 12,
//     WdfRequestSetInformation   = 13,
//     WdfRequestMaximum
//
// } WDF_REQUEST_TYPE, *PWDF_REQUEST_TYPE;

typedef enum _WDF_REQUEST_STOP_ACTION_FLAGS {
    WdfRequestStopActionInvalid          = 0x00000000,
    WdfRequestStopActionSuspend          = 0x00000001,
    WdfRequestStopActionPurge            = 0x00000002,
    WdfRequestStopRequestCancelable      = 0x10000000
} WDF_REQUEST_STOP_ACTION_FLAGS;

typedef enum _WDF_REQUEST_SEND_OPTIONS_FLAGS {
    WDF_REQUEST_SEND_OPTION_TIMEOUT                      = 0x00000001,
    WDF_REQUEST_SEND_OPTION_SYNCHRONOUS                  = 0x00000002,
    WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE          = 0x00000004,
    WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET              = 0x00000008,
    WDF_REQUEST_SEND_OPTION_IMPERSONATE_CLIENT           = 0x00010000,
    WDF_REQUEST_SEND_OPTION_IMPERSONATION_IGNORE_FAILURE = 0x00020000
} WDF_REQUEST_SEND_OPTIONS_FLAGS;


typedef enum _WDF_IO_TARGET_STATE
{
    WdfIoTargetStateUndefined       = 0,
    WdfIoTargetStarted              = 1,
    WdfIoTargetStopped              = 2,
    WdfIoTargetClosedForQueryRemove = 3,
    WdfIoTargetClosed               = 4,
    WdfIoTargetDeleted              = 5,
    WdfIoTargetStateMaximum
} WDF_IO_TARGET_STATE, *PWDF_IO_TARGET_STATE;

typedef enum _WDF_IO_TARGET_SENT_IO_ACTION
{
    WdfIoTargetSentIoUndefined          = 0,
    WdfIoTargetCancelSentIo             = 1,
    WdfIoTargetWaitForSentIoToComplete  = 2,
    WdfIoTargetLeaveSentIoPending       = 3,
    WdfIoTargetSentIoMaximum
} WDF_IO_TARGET_SENT_IO_ACTION;

typedef enum _WDF_PROPERTY_STORE_RETRIEVE_FLAGS
{
    WdfPropertyStoreNormal          = 0x00,
    WdfPropertyStoreCreateIfMissing = 0x01,
    WdfPropertyStoreCreateVolatile  = 0x02,

    WdfPropertyStoreRetrieveFlagsMask = WdfPropertyStoreNormal          |
                                        WdfPropertyStoreCreateIfMissing |
                                        WdfPropertyStoreCreateVolatile
} WDF_PROPERTY_STORE_RETRIEVE_FLAGS;


// #define __stdcall __attribute__((stdcall))
// typedef HRESULT __stdcall DLLGetClassObject_t(void*, void*, void**);


// /* ----------------- DLLGetClassObject typedef ------------------ */
// typedef HRESULT (STDAPICALLTYPE *DLLGetClassObject_t)(
//     REFGUID rclsid,
//     REFIID riid,
//     void **ppv
// );

/* ----------------- C++ COM-style Interfaces ------------------ */

class IClassFactory {
public:
    virtual HRESULT STDAPICALLTYPE QueryInterface(REFIID riid, void **ppvObject) = 0;
    virtual ULONG   STDAPICALLTYPE AddRef() = 0;
    virtual ULONG   STDAPICALLTYPE Release() = 0;
    virtual HRESULT STDAPICALLTYPE CreateInstance(void *outer, REFIID riid, void **ppvObject) = 0;
    virtual HRESULT STDAPICALLTYPE LockServer(BOOL lock) = 0;
};

class IUnknown {
public:
    virtual HRESULT STDAPICALLTYPE QueryInterface(REFIID riid, void **ppvObject) = 0;
    virtual ULONG   STDAPICALLTYPE AddRef() = 0;
    virtual ULONG   STDAPICALLTYPE Release() = 0;
};

class IWDFObject : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) = 0;
    virtual HRESULT STDMETHODCALLTYPE AssignContext( 
        void *pCleanupCallback,
        void *pContext) = 0;
    virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
        void **ppvContext) = 0;
    virtual void STDMETHODCALLTYPE AcquireLock( void) = 0; // 7
    virtual void STDMETHODCALLTYPE ReleaseLock( void) = 0; // 8
};


class IDriverEntry {
public:
    virtual HRESULT STDAPICALLTYPE QueryInterface(REFIID riid, void **ppvObject) = 0;
    virtual ULONG   STDAPICALLTYPE AddRef() = 0;
    virtual ULONG   STDAPICALLTYPE Release() = 0;

    virtual HRESULT STDAPICALLTYPE OnInitialize(void *driverHost) = 0;
    virtual HRESULT STDAPICALLTYPE OnDeviceAdd(void *wdfDriver, void *wdfDeviceInit) = 0;
    virtual HRESULT STDAPICALLTYPE OnDeinitialize(void* driver) = 0;
};


class IWDFDriver;
class IWDFIoRequest;
class IWDFFile;
class IQueueCallbackStateChange;
class IWDFIoTarget;
class IWDFDriverCreatedFile;
class IWDFIoQueue;
class IWDFDeviceInitialize;
class IWDFMemory;
class IWDFNamedPropertyStore;


class IWDFDevice : public IWDFObject
{
public:
    virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore(  // 9
        /* [annotation][unique][in] */ 
        _In_opt_  PCWSTR pcwszServiceName,
        /* [annotation][in] */ 
        _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
        /* [annotation][out] */ 
        _Out_  IWDFNamedPropertyStore **ppPropStore,
        /* [annotation][unique][out] */ 
        _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition) = 0;
    
    virtual void STDMETHODCALLTYPE GetDriver(   // 10
        /* [annotation][out] */ 
        _Out_  IWDFDriver **ppWdfDriver) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId(   // 11
        /* [annotation][unique][out][string] */ 
        _Out_opt_  PWSTR Buffer,
        /* [annotation][out][in] */ 
        _Inout_  DWORD *pdwSizeInChars) = 0;
    
    virtual void STDMETHODCALLTYPE GetDefaultIoTarget(  // 12
        /* [annotation][out] */ 
        _Out_  IWDFIoTarget **ppWdfIoTarget) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateWdfFile(   // 13
        /* [annotation][string][unique][in] */ 
        _In_opt_  LPCWSTR pcwszFileName,
        /* [annotation][out] */ 
        _Out_  IWDFDriverCreatedFile **ppFile) = 0;
    
    virtual void STDMETHODCALLTYPE GetDefaultIoQueue(   // 13
        /* [annotation][out] */ 
        _Out_  IWDFIoQueue **ppWdfIoQueue) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateIoQueue(  // 14
        /* [annotation][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][in] */ 
        _In_  BOOL bDefaultQueue,
        /* [annotation][in] */ 
        _In_  WDF_IO_QUEUE_DISPATCH_TYPE DispatchType,
        /* [annotation][in] */ 
        _In_  BOOL bPowerManaged,
        /* [annotation][in] */ 
        _In_  BOOL bAllowZeroLengthRequests,
        /* [annotation][out] */ 
        _Out_  IWDFIoQueue **ppIoQueue) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateDeviceInterface(   // 15
        /* [annotation][in] */ 
        _In_  LPCGUID pDeviceInterfaceGuid,
        /* [annotation][unique][string][in] */ 
        _In_opt_  PCWSTR pReferenceString) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE AssignDeviceInterfaceState(  // 16
        /* [annotation][in] */ 
        _In_  LPCGUID pDeviceInterfaceGuid,
        /* [annotation][unique][string][in] */ 
        _In_opt_  PCWSTR pReferenceString,
        /* [annotation][in] */ 
        _In_  BOOL Enable) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceName(  // 17
        /* [annotation][unique][out][string] */ 
        char16_t* pDeviceName,
        /* [annotation][out][in] */ 
        _Inout_  DWORD *pdwDeviceNameLength) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE PostEvent( // 18
        /* [annotation][in] */ 
        _In_  REFGUID EventGuid,
        /* [annotation][in] */ 
        _In_  WDF_EVENT_TYPE EventType,
        /* [annotation][size_is][in] */ 
        BYTE *pbData,
        /* [annotation][in] */ 
        _In_  DWORD cbDataSize) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching(  // 19
        /* [annotation][in] */ 
        _In_  IWDFIoQueue *pQueue,
        /* [annotation][in] */ 
        _In_  WDF_REQUEST_TYPE RequestType,
        /* [annotation][in] */ 
        _In_  BOOL Forward) = 0;
    
    virtual void STDMETHODCALLTYPE SetPnpState( 
        /* [annotation][in] */ 
        _In_  WDF_PNP_STATE State,
        /* [annotation][in] */ 
        _In_  WDF_TRI_STATE Value) = 0;
    
    virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpState( 
        /* [annotation][in] */ 
        _In_  WDF_PNP_STATE State) = 0;
    
    virtual void STDMETHODCALLTYPE CommitPnpState( void) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateRequest( 
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][unique][in] */ 
        _In_opt_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  IWDFIoRequest **ppRequest) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLink( 
        /* [annotation][unique][string][in] */ 
        _In_  PCWSTR pSymbolicLink) = 0;
    
};

class IWDFDevice2 : public IWDFDevice
{
public:
    virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettings( 
        /* [annotation][in] */ 
        _In_  WDF_POWER_POLICY_S0_IDLE_CAPABILITIES IdleCaps,
        /* [annotation][in] */ 
        _In_  DEVICE_POWER_STATE DxState,
        /* [annotation][in] */ 
        _In_  ULONG IdleTimeout,
        /* [annotation][in] */ 
        _In_  WDF_POWER_POLICY_S0_IDLE_USER_CONTROL UserControlOfIdleSettings,
        /* [annotation][in] */ 
        _In_  WDF_TRI_STATE Enabled) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE StopIdle( 
        /* [annotation][in] */ 
        _In_  BOOL WaitForD0) = 0;
    
    virtual void STDMETHODCALLTYPE ResumeIdle( void) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLinkWithReferenceString( 
        /* [annotation][unique][string][in] */ 
        _In_  PCWSTR pSymbolicLink,
        /* [annotation][unique][string][in] */ 
        _In_opt_  PCWSTR pReferenceString) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RegisterRemoteInterfaceNotification( 
        /* [annotation][in] */ 
        _In_  LPCGUID pDeviceInterfaceGuid,
        /* [annotation][in] */ 
        _In_  BOOL IncludeExistingInterfaces) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateRemoteInterface( 
        /* [annotation][in] */ 
        _In_  void *pRemoteInterfaceInit,
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][out] */ 
        _Out_  void **ppRemoteInterface) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateRemoteTarget( 
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][unique][in] */ 
        _In_opt_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  void **ppRemoteTarget) = 0;
    
    virtual void STDMETHODCALLTYPE GetDeviceStackIoTypePreference( 
        /* [annotation][out] */ 
        _Out_  WDF_DEVICE_IO_TYPE *ReadWritePreference,
        /* [annotation][out] */ 
        _Out_  WDF_DEVICE_IO_TYPE *IoControlPreference) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE AssignSxWakeSettings( 
        /* [annotation][in] */ 
        _In_  DEVICE_POWER_STATE DxState,
        /* [annotation][in] */ 
        _In_  WDF_POWER_POLICY_SX_WAKE_USER_CONTROL UserControlOfWakeSettings,
        /* [annotation][in] */ 
        _In_  WDF_TRI_STATE Enabled) = 0;
    
    virtual POWER_ACTION STDMETHODCALLTYPE GetSystemPowerAction( void) = 0;
    
};

class IWDFDevice3 : public IWDFDevice2
{
public:
    virtual HRESULT STDMETHODCALLTYPE MapIoSpace( 
        /* [annotation][in] */ 
        _In_  PHYSICAL_ADDRESS PhysicalAddress,
        /* [annotation][in] */ 
        _In_  SIZE_T NumberOfBytes,
        /* [annotation][in] */ 
        _In_  MEMORY_CACHING_TYPE CacheType,
        /* [annotation][out] */ 
        _Out_  void **pPseudoBaseAddress) = 0;
    
    virtual void STDMETHODCALLTYPE UnmapIoSpace( 
        /* [annotation][in] */ 
        _In_  void *PseudoBaseAddress,
        /* [annotation][in] */ 
        _In_  SIZE_T NumberOfBytes) = 0;
    
    virtual void *STDMETHODCALLTYPE GetHardwareRegisterMappedAddress( 
        /* [annotation][in] */ 
        _In_  void *PseudoBaseAddress) = 0;
    
    virtual SIZE_T STDMETHODCALLTYPE ReadFromHardware( 
        /* [annotation][in] */ 
        _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
        /* [annotation][in] */ 
        _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
        /* [annotation][in] */ 
        _In_  void *Address,
        /* [annotation][out] */ 
        void *Buffer,
        /* [annotation][in] */ 
        _In_opt_  ULONG Count) = 0;
    
    virtual void STDMETHODCALLTYPE WriteToHardware( 
        /* [annotation][in] */ 
        _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
        /* [annotation][in] */ 
        _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
        /* [annotation][in] */ 
        _In_  void *Address,
        /* [annotation][in] */ 
        _In_  SIZE_T Value,
        /* [annotation][in] */ 
        void *Buffer,
        /* [annotation][in] */ 
        _In_opt_  ULONG Count) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateInterrupt( 
        /* [annotation][in] */ 
        _In_  void* Configuration,
        /* [annotation][out] */ 
        _Out_  void **ppInterrupt) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateWorkItem( 
        /* [annotation][in] */ 
        _In_  void* pConfig,
        /* [annotation][in] */ 
        _In_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  void **ppWorkItem) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettingsEx( 
        /* [annotation][in] */ 
        _In_  PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS IdleSettings) = 0;
    
};

class IPnpCallbackHardware : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE OnPrepareHardware( 
        IWDFDevice *pWdfDevice) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE OnReleaseHardware( 
        IWDFDevice *pWdfDevice) = 0;
        
};

typedef enum _WDF_POWER_DEVICE_STATE {
    WdfPowerDeviceInvalid = 0,
    WdfPowerDeviceD0,
    WdfPowerDeviceD1,
    WdfPowerDeviceD2,
    WdfPowerDeviceD3,
    WdfPowerDeviceD3Final,
    WdfPowerDevicePrepareForHibernation,
    WdfPowerDeviceMaximum,
} WDF_POWER_DEVICE_STATE;

class IPnpCallback : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE OnD0Entry( 
        _In_  IWDFDevice *pWdfDevice,
        _In_  WDF_POWER_DEVICE_STATE previousState) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE OnD0Exit( 
        _In_  IWDFDevice *pWdfDevice,
        _In_  WDF_POWER_DEVICE_STATE newState) = 0;
    
    virtual void STDMETHODCALLTYPE OnSurpriseRemoval( 
        _In_  IWDFDevice *pWdfDevice) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE OnQueryRemove( 
        _In_  IWDFDevice *pWdfDevice) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE OnQueryStop( 
        _In_  IWDFDevice *pWdfDevice) = 0;
    
};


/* ----------------- Stub Implementations ------------------ */

class StubClassFactory : public IClassFactory {
public:
    HRESULT STDAPICALLTYPE QueryInterface(REFIID, void **ppvObject) override {
        std::cout << "IClassFactory::QueryInterface" << std::endl;
        if (ppvObject) *ppvObject = this;
        return 0;
    }
    ULONG STDAPICALLTYPE AddRef() override {
        std::cout << "IClassFactory::AddRef" << std::endl;
        return 1;
    }
    ULONG STDAPICALLTYPE Release() override {
        std::cout << "IClassFactory::Release" << std::endl;
        return 1;
    }
    HRESULT STDAPICALLTYPE CreateInstance(void *, REFIID, void **ppvObject) override {
        std::cout << "IClassFactory::CreateInstance" << std::endl;
        if (ppvObject) *ppvObject = nullptr;
        return 0;
    }
    HRESULT STDAPICALLTYPE LockServer(BOOL lock) override {
        std::cout << "IClassFactory::LockServer lock=" << lock << std::endl;
        return 0;
    }
};

class IWDFDriver : public IWDFObject
{
public:
    virtual HRESULT STDMETHODCALLTYPE CreateDevice( 
        /* [annotation][in] */ 
        _In_  IWDFDeviceInitialize *pDeviceInit,
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][out] */ 
        _Out_  IWDFDevice **ppDevice) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateWdfObject( 
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][unique][in] */ 
        _In_opt_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  IWDFObject **ppWdfObject) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreatePreallocatedWdfMemory( 
        /* [annotation][size_is][in] */ 
        BYTE *pBuff,
        /* [annotation][in] */ 
        _In_  SIZE_T BufferSize,
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][unique][in] */ 
        _In_opt_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  IWDFMemory **ppWdfMemory) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CreateWdfMemory( 
        /* [annotation][in] */ 
        _In_  SIZE_T BufferSize,
        /* [annotation][unique][in] */ 
        _In_opt_  IUnknown *pCallbackInterface,
        /* [annotation][unique][in] */ 
        _In_opt_  IWDFObject *pParentObject,
        /* [annotation][out] */ 
        _Out_  IWDFMemory **ppWdfMemory) = 0;
    
    virtual BOOL STDMETHODCALLTYPE IsVersionAvailable( 
        /* [annotation][in] */ 
        _In_  void *pMinimumVersion) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveVersionString( 
        /* [annotation][unique][out][string] */ 
        PWSTR pVersion,
        /* [annotation][out][in] */ 
        _Inout_  DWORD *pdwVersionLength) = 0;
    
};

typedef enum _WDF_PROPERTY_STORE_ROOT_CLASS {
  WdfPropertyStoreRootClassHardwareKey,
  WdfPropertyStoreRootClassSoftwareKey,
  WdfPropertyStoreRootClassDeviceInterfaceKey,
  WdfPropertyStoreRootClassLegacyHardwareKey
} WDF_PROPERTY_STORE_ROOT_CLASS;

typedef struct _WDF_PROPERTY_STORE_ROOT {
  ULONG                         LengthCb;
  WDF_PROPERTY_STORE_ROOT_CLASS RootClass;
  union {
    struct {
      PCWSTR ServiceName;
    } HardwareKey;
    struct {
      LPCGUID InterfaceGUID;
      PCWSTR  ReferenceString;
    } DeviceInterfaceKey;
    struct {
      PCWSTR LegacyMapName;
    } LegacyHardwareKey;
  } Qualifier;
} WDF_PROPERTY_STORE_ROOT, *PWDF_PROPERTY_STORE_ROOT;

class IWDFNamedPropertyStore : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE GetNamedValue( 
        _In_  LPCWSTR pszName,
        _Out_  PROPVARIANT *pv) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE SetNamedValue( 
        _In_  LPCWSTR pszName,
        _In_  const PROPVARIANT *pv) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE GetNameCount( 
        _Out_  DWORD *pdwCount) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE GetNameAt( 
        _In_  DWORD iProp,
        _Out_  PWSTR *ppwszName) = 0;
};

class IWDFNamedPropertyStore2 : public IWDFNamedPropertyStore
{
public:
    virtual HRESULT STDMETHODCALLTYPE DeleteNamedValue( 
        /* [annotation][string][in] */ 
        _In_  LPCWSTR pwszName) = 0;
    
};

typedef WDFMEMORY_OFFSET* PWDFMEMORY_OFFSET;

class IWDFMemory : public IWDFObject
{
public:
    virtual HRESULT STDMETHODCALLTYPE CopyFromMemory( 
        _In_  IWDFMemory *Source,
        _In_opt_  PWDFMEMORY_OFFSET SourceOffset) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CopyToBuffer( 
        _In_  ULONG_PTR SourceOffset,
        void *TargetBuffer,
        _In_  SIZE_T NumOfBytesToCopyTo) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE CopyFromBuffer( 
        _In_  ULONG_PTR DestOffset,
        void *SourceBuffer,
        _In_  SIZE_T NumOfBytesToCopyFrom) = 0;
    
    virtual SIZE_T STDMETHODCALLTYPE GetSize( void) = 0;
    
    virtual void *STDMETHODCALLTYPE GetDataBuffer( 
        SIZE_T *BufferSize) = 0;
    
    virtual void STDMETHODCALLTYPE SetBuffer( 
        void *Buffer,
        SIZE_T BufferSize) = 0;
};


class IWDFIoQueue : public IWDFObject
{
public:
    virtual void STDMETHODCALLTYPE GetDevice( 
        /* [annotation][out] */ 
        _Out_  IWDFDevice **ppWdfDevice) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching( 
        /* [annotation][in] */ 
        _In_  WDF_REQUEST_TYPE RequestType,
        /* [annotation][in] */ 
        _In_  BOOL Forward) = 0;
    
    virtual WDF_IO_QUEUE_STATE STDMETHODCALLTYPE GetState( 
        /* [annotation][out] */ 
        _Out_  ULONG *pulNumOfRequestsInQueue,
        /* [annotation][out] */ 
        _Out_  ULONG *pulNumOfRequestsInDriver) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequest( 
        /* [annotation][out] */ 
        _Out_  IWDFIoRequest **ppRequest) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequestByFileObject( 
        /* [annotation][in] */ 
        _In_  IWDFFile *pFile,
        /* [annotation][out] */ 
        _Out_  IWDFIoRequest **ppRequest) = 0;
    
    virtual void STDMETHODCALLTYPE Start( void) = 0;
    
    virtual void STDMETHODCALLTYPE Stop( 
        /* [annotation][unique][in] */ 
        _In_opt_  IQueueCallbackStateChange *pStopComplete) = 0;
    
    virtual void STDMETHODCALLTYPE StopSynchronously( void) = 0;
    
    virtual void STDMETHODCALLTYPE Drain( 
        /* [annotation][unique][in] */ 
        _In_opt_  IQueueCallbackStateChange *pDrainComplete) = 0;
    
    virtual void STDMETHODCALLTYPE DrainSynchronously( void) = 0;
    
    virtual void STDMETHODCALLTYPE Purge( 
        /* [annotation][unique][in] */ 
        _In_opt_  IQueueCallbackStateChange *pPurgeComplete) = 0;
    
    virtual void STDMETHODCALLTYPE PurgeSynchronously( void) = 0;
    
};

class IWDFRequestCompletionParams : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE GetCompletionStatus( void) = 0;
    
    virtual ULONG_PTR STDMETHODCALLTYPE GetInformation( void) = 0;
    
    virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetCompletedRequestType( void) = 0;
};


typedef enum _SECURITY_IMPERSONATION_LEVEL {
  SecurityAnonymous,
  SecurityIdentification,
  SecurityImpersonation,
  SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

class IWDFIoRequest : public IWDFObject
{
public:
    virtual void STDMETHODCALLTYPE CompleteWithInformation( 
        /* [annotation][in] */ 
        _In_  HRESULT CompletionStatus,
        /* [annotation][in] */ 
        _In_  SIZE_T Information) = 0;
    
    virtual void STDMETHODCALLTYPE SetInformation( 
        /* [annotation][in] */ 
        _In_  ULONG_PTR Information) = 0;
    
    virtual void STDMETHODCALLTYPE Complete( 
        /* [annotation][in] */ 
        _In_  HRESULT CompletionStatus) = 0;
    
    virtual void STDMETHODCALLTYPE SetCompletionCallback( 
        /* [annotation][in] */ 
        _In_  void *pCompletionCallback,
        /* [annotation][unique][in] */ 
        _In_opt_  void *pContext) = 0;
    
    virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetType( void) = 0;
    
    virtual void STDMETHODCALLTYPE GetCreateParameters( 
        /* [annotation][unique][out] */ 
        _Out_opt_  ULONG *pOptions,
        /* [annotation][unique][out] */ 
        _Out_opt_  USHORT *pFileAttributes,
        /* [annotation][unique][out] */ 
        _Out_opt_  USHORT *pShareAccess) = 0;
    
    virtual void STDMETHODCALLTYPE GetReadParameters( 
        /* [annotation][unique][out] */ 
        _Out_opt_  SIZE_T *pSizeInBytes,
        /* [annotation][unique][out] */ 
        _Out_opt_  LONGLONG *pullOffset,
        /* [annotation][unique][out] */ 
        _Out_opt_  ULONG *pulKey) = 0;
    
    virtual void STDMETHODCALLTYPE GetWriteParameters( 
        /* [annotation][unique][out] */ 
        _Out_opt_  SIZE_T *pSizeInBytes,
        /* [annotation][unique][out] */ 
        _Out_opt_  LONGLONG *pullOffset,
        /* [annotation][unique][out] */ 
        _Out_opt_  ULONG *pulKey) = 0;
    
    /// !!!
    virtual void STDMETHODCALLTYPE GetDeviceIoControlParameters( 
        /* [annotation][unique][out] */ 
        _Out_opt_  ULONG *pControlCode,
        /* [annotation][unique][out] */ 
        _Out_opt_  SIZE_T *pInBufferSize,
        /* [annotation][unique][out] */ 
        _Out_opt_  SIZE_T *pOutBufferSize) = 0;
    
    virtual void STDMETHODCALLTYPE GetOutputMemory( 
        /* [annotation][out] */ 
        _Out_  IWDFMemory **ppWdfMemory) = 0;
    
    virtual void STDMETHODCALLTYPE GetInputMemory( 
        /* [annotation][out] */ 
        _Out_  IWDFMemory **ppWdfMemory) = 0;
    
    virtual void STDMETHODCALLTYPE MarkCancelable( 
        /* [annotation][in] */ 
        _In_  void* pCancelCallback) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE UnmarkCancelable( void) = 0;
    
    virtual BOOL STDMETHODCALLTYPE CancelSentRequest( void) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE ForwardToIoQueue( 
        /* [annotation][in] */ 
        _In_  IWDFIoQueue *pDestination) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE Send( 
        /* [annotation][in] */ 
        _In_  /*IWDFIoTarget*/ void *pIoTarget,
        /* [annotation][in] */ 
        _In_  ULONG Flags,
        /* [annotation][in] */ 
        _In_  LONGLONG Timeout) = 0;
    
    virtual void STDMETHODCALLTYPE GetFileObject( 
        /* [annotation][out] */ 
        _Out_  void** ppFileObject) = 0;
    
    virtual void STDMETHODCALLTYPE FormatUsingCurrentType( void) = 0;
    
    virtual ULONG STDMETHODCALLTYPE GetRequestorProcessId( void) = 0;
    
    virtual void STDMETHODCALLTYPE GetIoQueue( 
        /* [annotation][out] */ 
        _Out_  IWDFIoQueue **ppWdfIoQueue) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE Impersonate( 
        /* [annotation][in] */ 
        _In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        /* [annotation][in] */ 
        _In_  void* pCallback,
        /* [annotation][unique][in] */ 
        _In_opt_  void *pvCallbackContext) = 0;
    
    virtual BOOL STDMETHODCALLTYPE IsFrom32BitProcess( void) = 0;
    
    virtual void STDMETHODCALLTYPE GetCompletionParams( 
        /* [annotation][out] */ 
        _Out_  IWDFRequestCompletionParams **ppCompletionParams) = 0;
    
};

class IWDFDeviceInitialize : public IUnknown
{
public:
    virtual void STDMETHODCALLTYPE SetFilter( void) = 0;
    
    virtual void STDMETHODCALLTYPE SetLockingConstraint( 
        /* [annotation][in] */ 
        _In_  WDF_CALLBACK_CONSTRAINT LockType) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
        /* [annotation][unique][in] */ 
        _In_opt_  PCWSTR pcwszServiceName,
        /* [annotation][in] */ 
        _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
        /* [annotation][out] */ 
        _Out_  IWDFNamedPropertyStore **ppPropStore,
        /* [annotation][unique][out] */ 
        _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition) = 0;
    
    virtual void STDMETHODCALLTYPE SetPowerPolicyOwnership( 
        /* [annotation][in] */ 
        _In_  BOOL fTrue) = 0;
    
    virtual void STDMETHODCALLTYPE AutoForwardCreateCleanupClose( 
        /* [annotation][in] */ 
        _In_  WDF_TRI_STATE State) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId( 
        /* [annotation][unique][out][string] */ 
        _Out_opt_  PWSTR Buffer,
        /* [annotation][out][in] */ 
        _Inout_  DWORD *pdwSizeInChars) = 0;
    
    virtual void STDMETHODCALLTYPE SetPnpCapability( 
        /* [annotation][in] */ 
        _In_  WDF_PNP_CAPABILITY Capability,
        /* [annotation][in] */ 
        _In_  WDF_TRI_STATE Value) = 0;
    
    virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpCapability( 
        /* [annotation][in] */ 
        _In_  WDF_PNP_CAPABILITY Capability) = 0;
    
};

class IWDFPropertyStoreFactory : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
        _In_  PWDF_PROPERTY_STORE_ROOT RootSpecifier,
        /* [annotation][in] */ 
        _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
        /* [annotation][in] */ 
        _In_  DWORD DesiredAccess,
        /* [annotation][unique][in] */ 
        _In_opt_  PCWSTR SubkeyPath,
        /* [annotation][out] */ 
        _Out_  IWDFNamedPropertyStore2 **PropertyStore,
        /* [annotation][unique][out] */ 
        _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *Disposition) = 0;
    
};

class IQueueCallbackDeviceIoControl : public IUnknown
{
public:
    virtual void STDMETHODCALLTYPE OnDeviceIoControl( 
        /* [annotation][in] */ 
        _In_  IWDFIoQueue *pWdfQueue,
        /* [annotation][in] */ 
        _In_  IWDFIoRequest *pWdfRequest,
        /* [annotation][in] */ 
        _In_  ULONG ControlCode,
        /* [annotation][in] */ 
        _In_  SIZE_T InputBufferSizeInBytes,
        /* [annotation][in] */ 
        _In_  SIZE_T OutputBufferSizeInBytes) = 0;
    
};


#endif
