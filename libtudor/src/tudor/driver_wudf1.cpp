#include "winapi/windows.h"
#include "internal.h"
// #include <ksguid.h>
#include <stdio.h>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <codecvt>
#include <string>
#include <locale>

#define _Analysis_mode_(...)
#define _Notliteral_
#define __user_driver
#define _Out_writes_bytes_opt_
#define _In_reads_bytes_opt_(...)

#include "wudf1_minimal.h"

// #include "winbio_ioctl.h"

#define NTDDI_VERSION NTDDI_WIN7

// extern "C" {
// HRESULT PropVariantToInt32(REFPROPVARIANT propvarIn, LONG *ret);
//
// int PropVariantToStringAlloc(
//   REFPROPVARIANT propvar,
//   PWSTR          *ppszOut
// );
// }

// typedef DllGetClassObject_t(_In_ REFCLSID rclsid, _In_ REFIID riid, _Out_ LPVOID* ppv);


IDriverEntry *inst = NULL;
IWDFDriver* aDriver = NULL;

bool tudor_log_traces = true;

int goIdle = 0;

static winmodule ntdll_module = {
    .name = "ntdll.dll",
    .cmdline = "ntdll.dll",
    .environ = (const char*[]) { NULL }
};

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3
typedef BOOL __winfnc (*api_DllMain)(HANDLE hinstDLL, int fdwReason, void *lpReserved);

struct windrv_dll *tudor_adapter_dll, *tudor_driver_dll;
WINBIO_SENSOR_INTERFACE *tudor_sensor_adapter;
WINBIO_ENGINE_INTERFACE *tudor_engine_adapter;

static DRIVER_OBJECT umdf_driver;
struct winwdf_driver *tudor_wdf_driver;

extern uint8_t _binary_libtudor_synaAdvAdapter_dll_start, _binary_libtudor_synaAdvAdapter_dll_end;
extern uint8_t _binary_libtudor_synaWudfBioUsb_dll_start, _binary_libtudor_synaWudfBioUsb_dll_end;

#define NUM_WINDRV_DLLS 2
struct windrv_dll tudor_windrv_dlls[] = {
    {
        .module = {
            .name = "synaWudfBioUsb.dll",
            .cmdline = "synaWudfBioUsb.dll",
            .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaWudfBioUsb_dll_start, .pe_image_end = &_binary_libtudor_synaWudfBioUsb_dll_end,
        .is_adapter = false, .is_driver = true
    },
    {
        .module = {
            .name = "synaAdvAdapter.dll",
            .cmdline = "synaAdvAdapter.dll",
            .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaAdvAdapter_dll_start, .pe_image_end = &_binary_libtudor_synaAdvAdapter_dll_end,
        .is_adapter = true, .is_driver = false
    }
};



#define DEFINE_GUID11(name, a, b, c, d, e, f, g, h, i, j, k) \
    static const GUID_DLL name = { \
        (a), (b), (c), \
        {(d), (e), (f), (g), (h), (i), (j), (k)} \
    }

// DEFINE_GUID11(SYNA_CLSID, 0x96710705, 0xb080, 0x4b29, 0xa3, 0xec, 0xb1, 0x69, 0x35, 0xae, 0x66, 0x3a);
DEFINE_GUID11(SYNA_CLSID, 0x96710705, 0xb080, 0x4b29, 0xa3, 0xec, 0xb1, 0x69, 0x35, 0xae, 0x66, 0x3a);


// 1BEC7499-8881-4F2B-B01C-A1A907304AFC
DEFINE_GUID11(IID_IDriverEntry, 0x1BEC7499, 0x8881, 0x4F2B, 0xB0, 0x1C, 0xA1, 0xA9, 0x07, 0x30, 0x4A, 0xFC);

DEFINE_GUID11(IID_IQueueCallbackDeviceIoControl, 0xC5411408, 0x0F1E, 0x4ed6, 0xA4, 0x12, 0x36, 0xDD, 0x15, 0xEE, 0xE7, 0x07);

DEFINE_GUID11(IID_IPnpCallbackHardware, 0x51433BD3, 0xC7C1, 0x4bd8, 0xB4, 0xC1, 0xAB, 0x1E, 0x03, 0x46, 0x26, 0xCC);

DEFINE_GUID11(IID_IPnpCallback, 0x27c32374, 0xcc45, 0x4840, 0x85, 0x7e, 0x8e, 0x5e, 0xf7, 0xc0, 0xeb, 0xff);

DEFINE_GUID11(IID_IWDFPropertyStoreFactory, 0x45BE7E06, 0x9B65, 0x434d, 0xA7, 0xD6, 0x95, 0x72, 0xD7, 0xF7, 0x3D, 0x53);

DEFINE_GUID11(IID_IUnknown, 0x00000000, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
// DEFINE_GUID11(IID_IUnknown, 0x00000001, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

DEFINE_GUID11( GUID_DEVINTERFACE_BIOMETRIC_READER,
             0xe2b5183a, 0x99ea, 0x4cc3, 0xad, 0x6b, 0x80, 0xca, 0x8d, 0x71, 0x5b, 0x80);

void print_guid(const GUID_DLL* g) {
    if (!g) {
        printf("NULL GUID pointer\n");
        return;
    }
    printf("{%08lX-%04hX-%04hX-", 
           g->Data1, g->Data2, g->Data3);
    // Print first 2 bytes of Data4
    printf("%02hhX%02hhX-", g->Data4[0], g->Data4[1]);
    // Print last 6 bytes of Data4
    printf("%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
           g->Data4[2], g->Data4[3], g->Data4[4], 
           g->Data4[5], g->Data4[6], g->Data4[7]);
    printf("\r\n");
}

bool StringFromIID(REFIID rclsid, LPOLESTR *lplpsz) {
    if (!rclsid || !lplpsz) {
        return false;
    }

    // Windows uses wide strings (OLESTR = wchar_t*)
    // Allocate enough space: 38 chars + 2 (braces + null) = 39
    // Wide chars, so malloc sizeof(wchar_t).
    const int len = 39;
    wchar_t *buf = (wchar_t *)malloc(sizeof(wchar_t) * (len + 1));
    if (!buf) {
        return false;
    }

    swprintf(buf, len + 1,
             L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             rclsid->Data1,
             rclsid->Data2,
             rclsid->Data3,
             rclsid->Data4[0], rclsid->Data4[1],
             rclsid->Data4[2], rclsid->Data4[3],
             rclsid->Data4[4], rclsid->Data4[5],
             rclsid->Data4[6], rclsid->Data4[7]);

    *lplpsz = buf;
    return true;
}

void* CoTaskMemAlloc(size_t cb)
{
    return malloc(cb);
}

void CoTaskMemFree(void* pv)
{
    free(pv);
}


bool IsEqualIID(REFIID riid1, REFIID riid2) {
    if (!riid1 || !riid2) return false;
    return memcmp(riid1, riid2, sizeof(GUID)) == 0;
}

std::string utf16le_to_utf8(const char16_t* input) {
    if (!input) return {};

    // Wrap raw pointer into std::u16string
    std::u16string u16str(input);

    // Convert UTF-16 to UTF-8
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    return convert.to_bytes(u16str);
}

char16_t* utf8_to_utf16le(const std::string& input) {
    // Converter from UTF-8 to UTF-16
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;

    std::u16string u16str = convert.from_bytes(input);

    // Allocate new buffer (+1 for null terminator)
    char16_t* buffer = new char16_t[u16str.size() + 1];

    // Copy content
    std::copy(u16str.begin(), u16str.end(), buffer);
    buffer[u16str.size()] = u'\0'; // null terminator

    return buffer; // caller must delete[]
}

struct IObjectCleanup;

class MyDevInit : public IWDFDeviceInitialize {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            printf("QueryInterface\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("Release\r\n");
            return 0;
        }

    public:
        virtual void STDMETHODCALLTYPE SetFilter( void) {
            printf("SetFilter\r\n");
        }
        
        virtual void STDMETHODCALLTYPE SetLockingConstraint( 
            /* [annotation][in] */ 
            _In_  WDF_CALLBACK_CONSTRAINT LockType) {
            printf("SetLockingConstraint: %d\r\n", (int)LockType);
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
            /* [annotation][unique][in] */ 
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */ 
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
            /* [annotation][out] */ 
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */ 
            _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition) {
            printf("RetrieveDevicePropertyStore\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE SetPowerPolicyOwnership( 
            /* [annotation][in] */ 
            _In_  BOOL fTrue) {
            printf("SetPowerPolicyOwnership\r\n");
        }
        
        virtual void STDMETHODCALLTYPE AutoForwardCreateCleanupClose( 
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE State) {
            printf("AutoForwardCreateCleanupClose\r\n");
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId( 
            /* [annotation][unique][out][string] */ 
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwSizeInChars) {
            printf("RetrieveDeviceInstanceId\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE SetPnpCapability( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_CAPABILITY Capability,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Value) {
            printf("SetPnpCapability\r\n");
        }
        
        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpCapability( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_CAPABILITY Capability) {
            printf("GetPnpCapability\r\n");
            return WdfFalse;
        }
};


struct MyNamedPropertyStore : public IWDFNamedPropertyStore2 {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            //printf("MyMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE GetNamedValue(  // 24
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pszName,
            /* [annotation][out] */ 
            _Out_  PROPVARIANT *pv){
            std::wcout << L"=====================================" << std::endl;
            std::wcout << L"GetNamedValue " << pszName << std::endl;
            std::string fname = utf16le_to_utf8(pszName);
            std::cout << fname << std::endl;
            std::wcout << L"=====================================" << std::endl;

            if(fname == "CalibrationData") {
                std::ifstream input(fname + ".blob", std::ios::binary);
                std::vector<char> buf((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
                std::cout << "Loaded " << buf.size() << " bytes of calibration data" << std::endl;
                if(buf.size() == 0) {
                    DECIMAL_SETZERO(pv->decVal);
                } else {
                    pv->vt = VT_BLOB;
                    pv->blob.cbSize = buf.size();
                    pv->blob.pBlobData = (BYTE*)CoTaskMemAlloc(pv->blob.cbSize);
                    std::copy(buf.begin(), buf.end(), pv->blob.pBlobData);
                }
            } 
            else if(fname == "LastUpdateSystemTimeStamp" || fname == "OldCalDataDeleted") {
                std::ifstream input(fname + ".uint");
                if(input) {
                    pv->vt = VT_UINT;
                    unsigned int& dst = pv->uintVal;
                    input >> dst;
                    std::cout << "UINT " << fname << " = " << pv->uintVal << std::endl; 
                }
                else {
                    DECIMAL_SETZERO(pv->decVal);
                    std::cout << "UINT " << fname << " not found" << std::endl; 
                }
            } 
            else {
                memset(pv, 0, sizeof(PROPVARIANT));
                // DECIMAL_SETZERO(pv->decVal);
                // pv->vt = VT_DECIMAL;
            }
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE SetNamedValue(  // 32
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pszName,
            /* [annotation][in] */ 
            _In_  const PROPVARIANT *pv){
            //wchar_t *buf = L"<error>";
            //LONG num = 118;
            //PropVariantToInt32(*pv, &num);
            //PropVariantToStringAlloc(*pv, &buf);

            std::wcout << L"=====================================" << std::endl;
            std::wcout << L"SetNamedValue " << pszName << "=" << pv->vt << std::endl;
            std::string str_u8 = utf16le_to_utf8(pszName);
            std::cout << str_u8 << std::endl;
            switch(pv->vt) {
                case VT_I1:
                    printf("VT_I1: %d\n", pv->cVal);
                    break;
                case VT_UINT: {
                        std::string fname = utf16le_to_utf8(pszName);
                        std::ofstream output(fname + ".uint");
                        output << pv->uintVal << std::endl;
                        printf("VT_UINT: %d\n", pv->uintVal);
                    }
                    break;
                case VT_BLOB: {
                        std::string fname = utf16le_to_utf8(pszName);
                        std::ofstream output(fname + ".blob", std::ios::binary);
                        std::copy(pv->blob.pBlobData, pv->blob.pBlobData + pv->blob.cbSize,
                                std::ostreambuf_iterator<char>(output));

                        char hex[800020], *p = hex;
                        for(unsigned int i=0;i<(pv->blob.cbSize < 400? pv->blob.cbSize : 400);i++) {
                            p+=sprintf(p, "%02x", pv->blob.pBlobData[i]);
                        }
                        *p=0;
                        printf("Blob value: %lu: %s\n", pv->blob.cbSize, hex);
                    }
                    break;
            }
            std::wcout << L"=====================================" << std::endl;
            //CoTaskMemFree(buf);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE GetNameCount( 
            /* [annotation][out] */ 
            _Out_  DWORD *pdwCount){
            std::wcout << L"GetNameCount " << std::endl;
            *pdwCount = 0;
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE GetNameAt( 
            /* [annotation][in] */ 
            _In_  DWORD iProp,
            /* [annotation][string][out] */ 
            _Out_  PWSTR *ppwszName){
            std::wcout << L"GetNameAt " << iProp << std::endl;
            *ppwszName = L"";
            return 0;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE DeleteNamedValue( 
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pwszName){
            std::wcout << L"DeleteNamedValue " << pwszName<< std::endl;
            return 0;
        }

};

struct MyMem : public IWDFMemory {
    public:
        MyMem(void *b, SIZE_T s) {
            buf = b;
            size = s;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            //printf("MyMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE CopyFromMemory( 
            /* [annotation][in] */ 
            _In_  IWDFMemory *Source,
            /* [annotation][unique][in] */ 
            _In_opt_  PWDFMEMORY_OFFSET SourceOffset){
            printf("CopyFromMemory\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CopyToBuffer( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR SourceOffset,
            /* [annotation][size_is][in] */ 
             void *TargetBuffer,
            /* [annotation][in] */ 
            _In_  SIZE_T NumOfBytesToCopyTo){
            printf("CopyToBuffer\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CopyFromBuffer( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR DestOffset,
            /* [annotation][size_is][in] */ 
            void *SourceBuffer,
            /* [annotation][in] */ 
            _In_  SIZE_T NumOfBytesToCopyFrom){
            printf("CopyFromBuffer\r\n");
            return 0;
        }

        
        virtual SIZE_T STDMETHODCALLTYPE GetSize( void){
            printf("GetSize\r\n");
            return size;
        }

        
        virtual void *STDMETHODCALLTYPE GetDataBuffer( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *BufferSize){
            if(BufferSize) {
                *BufferSize = size;
            }
            // Sleep(5000);
            return buf;
        }

        
        virtual void STDMETHODCALLTYPE SetBuffer( 
            /* [annotation][size_is][in] */ 
            void *Buffer,
            /* [annotation][in] */ 
            _In_  SIZE_T BufferSize){
            printf("SetBuffer\r\n");
            buf = Buffer;
            size = BufferSize;
        }

    void * buf;
    SIZE_T size;
};

struct MyRequest : public IWDFIoRequest {
    public:
        MyRequest(WDF_REQUEST_TYPE t, ULONG c, MyMem *out, MyMem *in) {
            reqType = t;
            ctl = c;
            outMem = out;
            inMem = in;
            complete = FALSE;
            informationSize = 0;
        }

        WDF_REQUEST_TYPE reqType;
        ULONG ctl;
        BOOL complete;
        LONG_PTR informationSize;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyRequest::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyRequest::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE CompleteWithInformation( 
            /* [annotation][in] */ 
            _In_  HRESULT CompletionStatus,
            /* [annotation][in] */ 
            _In_  SIZE_T Information){
            printf("CompleteWithInformation\r\n");
            complete = TRUE;
        }

        
        virtual void STDMETHODCALLTYPE SetInformation( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR Information){
            printf("SetInformation size=%lld\r\n", Information);
            informationSize = Information;
        }

        
        virtual void STDMETHODCALLTYPE Complete( 
            /* [annotation][in] */ 
            _In_  HRESULT CompletionStatus){
            printf("Complete: %lx\r\n", (unsigned long)CompletionStatus);
            complete = TRUE;
        }

        
        virtual void STDMETHODCALLTYPE SetCompletionCallback( 
            /* [annotation][in] */ 
            _In_  void *pCompletionCallback,
            /* [annotation][unique][in] */ 
            _In_opt_  void *pContext){
            printf("SetCompletionCallback\r\n");
        }

        
        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetType( void){
            printf("GetType\r\n");
            return reqType;
        }

        
        virtual void STDMETHODCALLTYPE GetCreateParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pOptions,
            /* [annotation][unique][out] */ 
            _Out_opt_  USHORT *pFileAttributes,
            /* [annotation][unique][out] */ 
            _Out_opt_  USHORT *pShareAccess){
            printf("GetCreateParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetReadParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */ 
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pulKey){
            printf("GetReadParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetWriteParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */ 
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pulKey){
            printf("GetWriteParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetDeviceIoControlParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pControlCode,
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pInBufferSize,
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pOutBufferSize){
            //printf("GetDeviceIoControlParameters %p %p %p\r\n", pControlCode, pInBufferSize, pOutBufferSize);
            *pControlCode = ctl;
            *pInBufferSize = inMem->size;
            *pOutBufferSize = outMem->size;
        }

        
        MyMem *outMem, *inMem;

        virtual void STDMETHODCALLTYPE GetOutputMemory( 
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory){
            *ppWdfMemory = outMem;
            //printf("GetOutputMemory\r\n");
        }
        
        virtual void STDMETHODCALLTYPE GetInputMemory( 
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory){
            *ppWdfMemory = inMem;
            // printf("GetInputMemory\r\n");
        }

        
        virtual void STDMETHODCALLTYPE MarkCancelable( 
            /* [annotation][in] */ 
            _In_  void *pCancelCallback){
            printf("MarkCancelable\r\n");
            //this->cancelCallback = pCancelCallback;
        }

        virtual HRESULT STDMETHODCALLTYPE UnmarkCancelable( void){
            printf("UnmarkCancelable\r\n");
            return 0;
        }

        
        virtual BOOL STDMETHODCALLTYPE CancelSentRequest( void){
            printf("CancelSentRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE ForwardToIoQueue( 
            /* [annotation][in] */ 
            _In_  IWDFIoQueue *pDestination){
            printf("ForwardToIoQueue\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE Send( 
            /* [annotation][in] */ 
            _In_  void *pIoTarget,
            /* [annotation][in] */ 
            _In_  ULONG Flags,
            /* [annotation][in] */ 
            _In_  LONGLONG Timeout){
            printf("Send\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetFileObject( 
            /* [annotation][out] */ 
            _Out_  void **ppFileObject){
            printf("GetFileObject\r\n");
        }

        
        virtual void STDMETHODCALLTYPE FormatUsingCurrentType( void){
            printf("FormatUsingCurrentType\r\n");
        }

        
        virtual ULONG STDMETHODCALLTYPE GetRequestorProcessId( void){
            printf("GetRequestorProcessId\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetIoQueue( 
            /* [annotation][out] */ 
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            printf("GetIoQueue\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE Impersonate( 
            /* [annotation][in] */ 
            _In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            /* [annotation][in] */ 
            _In_  void *pCallback,
            /* [annotation][unique][in] */ 
            _In_opt_  void *pvCallbackContext){
            printf("Impersonate\r\n");
            return 0;
        }

        
        virtual BOOL STDMETHODCALLTYPE IsFrom32BitProcess( void){
            printf("IsFrom32BitProcess\r\n");
            return 1;
        }

        
        virtual void STDMETHODCALLTYPE GetCompletionParams( 
            /* [annotation][out] */ 
            _Out_  IWDFRequestCompletionParams **ppCompletionParams){
            printf("GetCompletionParams\r\n");
        }

        
};

struct MyPropertyStoreFactory : public IWDFPropertyStoreFactory {
public:
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
        LPOLESTR str;
        StringFromIID(riid, &str);
        std::wcout << L"MyPropertyStoreFactory::QueryInterface " << str << std::endl;
        *ppvObject = this;
        printf("ppvObject=%p\r\n", *ppvObject);
        return 0; 
    }
    virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
        printf("AddRef\r\n");
        return 0; 
    }
    virtual ULONG STDMETHODCALLTYPE Release(void) {
        printf("MyPropertyStoreFactory::Release\r\n");
        return 0;
    }

public:
    virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
        /* [annotation][in] */ 
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
        _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *Disposition){


        printf("RetrieveDevicePropertyStore\r\n");
        *PropertyStore = new MyNamedPropertyStore();
        return 0;
    }

};

struct MyQueue : public IWDFIoQueue {
    public:
        MyQueue(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(&IID_IQueueCallbackDeviceIoControl, (LPVOID*)&ioctl);
            printf("ioctl=%p\r\n", ioctl);
        }

        IQueueCallbackDeviceIoControl *ioctl = NULL;

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyQueue::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyQueue::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE GetDevice( 
            /* [annotation][out] */ 
            _Out_  IWDFDevice **ppWdfDevice){
            printf("GetDevice\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching( 
            /* [annotation][in] */ 
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */ 
            _In_  BOOL Forward){
            printf("MyQueue::ConfigureRequestDispatching\r\n");
            return 0;
        }

        
        virtual WDF_IO_QUEUE_STATE STDMETHODCALLTYPE GetState( 
            /* [annotation][out] */ 
            _Out_  ULONG *pulNumOfRequestsInQueue,
            /* [annotation][out] */ 
            _Out_  ULONG *pulNumOfRequestsInDriver){
            printf("GetState\r\n");
            return (WDF_IO_QUEUE_STATE)(WdfIoQueueAcceptRequests | 
                    WdfIoQueueDispatchRequests | 
                    WdfIoQueueNoRequests | 
                    WdfIoQueueDriverNoRequests);
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequest( 
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("RetrieveNextRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequestByFileObject( 
            /* [annotation][in] */ 
            _In_  IWDFFile *pFile,
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("RetrieveNextRequestByFileObject\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE Start( void){
            printf("Start\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Stop( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pStopComplete){
            printf("Stop\r\n");
        }

        
        virtual void STDMETHODCALLTYPE StopSynchronously( void){
            printf("StopSynchronously\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Drain( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pDrainComplete){
            printf("Drain\r\n");
        }

        
        virtual void STDMETHODCALLTYPE DrainSynchronously( void){
            printf("Drain\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Purge( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pPurgeComplete){
            printf("Purge\r\n");
        }

        
        virtual void STDMETHODCALLTYPE PurgeSynchronously( void){
            printf("Purge\r\n");
        }


};


MyQueue *myQueue = NULL;



struct MyDevice : public IWDFDevice3 {
    public:
        MyDevice(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(&IID_IPnpCallbackHardware, (LPVOID*)&pnphwcb);
            pCallbackInterface->QueryInterface(&IID_IPnpCallback, (LPVOID*)&pnpcb);
            printf("pnphwcb=%p pnpcb=%p\r\n", pnphwcb, pnpcb);
        }

        IPnpCallbackHardware *pnphwcb;
        IPnpCallback *pnpcb;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyDevice::QueryInterface " << str << std::endl;

            if(IsEqualIID(riid, &IID_IWDFPropertyStoreFactory)) {
                printf("is IID_IWDFPropertyStoreFactory\r\n");
                *ppvObject = new MyPropertyStoreFactory();
            } else {
                printf("is IID_IWDFDevice3\r\n");
                *ppvObject = (IWDFDevice3*)this;
            }
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyDevice::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
            /* [annotation][unique][in] */ 
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */ 
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS  Flags,
            /* [annotation][out] */ 
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */ 
            WDF_PROPERTY_STORE_DISPOSITION* pDisposition){
            printf("RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new MyNamedPropertyStore();
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDriver( 
            /* [annotation][out] */ 
            _Out_  IWDFDriver **ppWdfDriver){
            printf("GetDriver\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId( 
            /* [annotation][unique][out][string] */ 
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwSizeInChars){
            printf("RetrieveDeviceInstanceId\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDefaultIoTarget( 
            /* [annotation][out] */ 
            _Out_  IWDFIoTarget **ppWdfIoTarget){
            printf("GetDefaultIoTarget\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfFile( 
            /* [annotation][string][unique][in] */ 
            _In_opt_  LPCWSTR pcwszFileName,
            /* [annotation][out] */ 
            _Out_  IWDFDriverCreatedFile **ppFile){
            printf("CreateWdfFile\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDefaultIoQueue( 
            /* [annotation][out] */ 
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            printf("GetDefaultIoQueue\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateIoQueue( 
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
            _Out_  IWDFIoQueue **ppIoQueue){
            printf("MyDevice::CreateIoQueue\r\n");
            *ppIoQueue = myQueue = new MyQueue(pCallbackInterface);
            printf("new queue=%p\r\n", *ppIoQueue);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateDeviceInterface( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString){
            //printf("CreateDeviceInterface\r\n");
            LPOLESTR str;
            StringFromIID(pDeviceInterfaceGuid, &str);
            std::wcout << L"MyDevice::CreateDeviceInterface "
                        << str
                        << std::endl;
            fflush(stdout);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignDeviceInterfaceState( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString,
            /* [annotation][in] */ 
            _In_  BOOL Enable){
            //printf("AssignDeviceInterfaceState\r\n");
            LPOLESTR str;
            StringFromIID(pDeviceInterfaceGuid, &str);
            std::wcout << L"MyDevice::AssignDeviceInterfaceState "
                        << str
                        << L"="
                        << Enable
                        << std::endl;
            fflush(stdout);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceName( 
            /* [annotation][unique][out][string] */ 
            char16_t* pDeviceName,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwDeviceNameLength)


        {
            printf("RetrieveDeviceName %p %p %u\r\n", pDeviceName, pdwDeviceNameLength, *pdwDeviceNameLength );
            fflush(stdout);

            if (!pdwDeviceNameLength) {
                return -1;
            }
            static const char16_t name[] = u"C:\\usb.txt";

            // Required length (including null terminator)
            DWORD requiredLength = static_cast<DWORD>(std::char_traits<char16_t>::length(name) + 1);

            if (pDeviceName == nullptr) {
                // Caller only wants the size
                *pdwDeviceNameLength = requiredLength;
                return 0;
            }

            if (*pdwDeviceNameLength < requiredLength) {
                // Buffer too small
                *pdwDeviceNameLength = requiredLength;
                return -1;
            }

            memcpy(pDeviceName, name, requiredLength * sizeof(char16_t));
            *pdwDeviceNameLength = requiredLength;

            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE PostEvent( 
            /* [annotation][in] */ 
            _In_  REFGUID EventGuid,
            /* [annotation][in] */ 
            _In_  WDF_EVENT_TYPE EventType,
            /* [annotation][size_is][in] */ 
            BYTE *pbData,
            /* [annotation][in] */ 
            _In_  DWORD cbDataSize){
            printf("PostEvent\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching( 
            /* [annotation][in] */ 
            _In_  IWDFIoQueue *pQueue,
            /* [annotation][in] */ 
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */ 
            _In_  BOOL Forward){
            printf("MyDevice::ConfigureRequestDispatching\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE SetPnpState( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_STATE State,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Value){
            printf("SetPnpState\r\n");
        }

        
        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpState( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_STATE State){
            printf("GetPnpState\r\n");
            return WdfFalse;
        }

        
        virtual void STDMETHODCALLTYPE CommitPnpState( void){
            printf("CommitPnpState\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRequest( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("CreateRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLink( 
            /* [annotation][unique][string][in] */ 
            _In_  PCWSTR pSymbolicLink){
            printf("CreateSymbolicLink\r\n");
            return 0;
        }

    // Device2
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
            _In_  WDF_TRI_STATE Enabled){
            printf("AssignS0IdleSettings\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE StopIdle( 
            /* [annotation][in] */ 
            _In_  BOOL WaitForD0){
            printf("StopIdle\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE ResumeIdle( void){
            goIdle = 1;
            printf("ResumeIdle\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLinkWithReferenceString( 
            /* [annotation][unique][string][in] */ 
            _In_  PCWSTR pSymbolicLink,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString){
            printf("CreateSymbolicLinkWithReferenceString\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RegisterRemoteInterfaceNotification( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][in] */ 
            _In_  BOOL IncludeExistingInterfaces){
            printf("RegisterRemoteInterfaceNotification\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRemoteInterface( 
            /* [annotation][in] */ 
            _In_  void *pRemoteInterfaceInit,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */ 
            _Out_  void **ppRemoteInterface){
            printf("CreateRemoteInterface\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRemoteTarget( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  void **ppRemoteTarget){
            printf("CreateRemoteTarget\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDeviceStackIoTypePreference( 
            /* [annotation][out] */ 
            _Out_  WDF_DEVICE_IO_TYPE *ReadWritePreference,
            /* [annotation][out] */ 
            _Out_  WDF_DEVICE_IO_TYPE *IoControlPreference){
            printf("GetDeviceStackIoTypePreference\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignSxWakeSettings( 
            /* [annotation][in] */ 
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */ 
            _In_  WDF_POWER_POLICY_SX_WAKE_USER_CONTROL UserControlOfWakeSettings,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Enabled){
            printf("AssignSxWakeSettings\r\n");
            return 0;
        }

        
        virtual POWER_ACTION STDMETHODCALLTYPE GetSystemPowerAction( void){
            printf("GetSystemPowerAction\r\n");
            return PowerActionNone;
        }

    // Device3
    public:
        virtual HRESULT STDMETHODCALLTYPE MapIoSpace( 
            /* [annotation][in] */ 
            _In_  PHYSICAL_ADDRESS PhysicalAddress,
            /* [annotation][in] */ 
            _In_  SIZE_T NumberOfBytes,
            /* [annotation][in] */ 
            _In_  MEMORY_CACHING_TYPE CacheType,
            /* [annotation][out] */ 
            _Out_  void **pPseudoBaseAddress){
            printf("MapIoSpace\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE UnmapIoSpace( 
            /* [annotation][in] */ 
            _In_  void *PseudoBaseAddress,
            /* [annotation][in] */ 
            _In_  SIZE_T NumberOfBytes){
            printf("UnmapIoSpace\r\n");
        }

        
        virtual void *STDMETHODCALLTYPE GetHardwareRegisterMappedAddress( 
            /* [annotation][in] */ 
            _In_  void *PseudoBaseAddress){
            printf("GetHardwareRegisterMappedAddress\r\n");
            return 0;
        }

        
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
            _In_opt_  ULONG Count){
            printf("ReadFromHardware\r\n");
            return 0;
        }

        
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
            _In_opt_  ULONG Count){
            printf("WriteToHardware\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateInterrupt( 
            /* [annotation][in] */ 
            _In_  void* Configuration,
            /* [annotation][out] */ 
            _Out_  void **ppInterrupt){
            printf("CreateInterrupt\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateWorkItem( 
            /* [annotation][in] */ 
            _In_  void* pConfig,
            /* [annotation][in] */ 
            _In_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  void **ppWorkItem){
            printf("CreateWorkItem\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettingsEx( 
            /* [annotation][in] */ 
            _In_  PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS IdleSettings){
            printf("AssignS0IdleSettingsEx\r\n");
            return 0;
        }

        
};

MyDevice* myDevice = NULL;


struct MyDriver : public IWDFDriver {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            printf("QueryInterface\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyDriver::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE CreateDevice( 
            /* [annotation][in] */ 
            _In_  IWDFDeviceInitialize *pDeviceInit,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */ 
            _Out_  IWDFDevice **ppDevice) {
            printf("[CreateDevice]\r\n");
            printf("pDevInit = %p\n", pDeviceInit);
            printf("pCallbackInterface = %p\n", pCallbackInterface);
            printf("ppDevice = %p\n", ppDevice);
            myDevice = new MyDevice(pCallbackInterface);
            *ppDevice = myDevice;
            printf("new device=%p\r\n", *ppDevice);
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfObject( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFObject **ppWdfObject) {
            printf("CreateWdfObject\r\n");
            return 0;
        }
        
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
            _Out_  IWDFMemory **ppWdfMemory) { 
            printf("CreatePreallocatedWdfMemory\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfMemory( 
            /* [annotation][in] */ 
            _In_  SIZE_T BufferSize,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory) { 
            printf("CreateWdfMemory\r\n");
            return 0;
        }
        
        virtual BOOL STDMETHODCALLTYPE IsVersionAvailable( 
            /* [annotation][in] */ 
            _In_  void *pMinimumVersion) { 
            printf("IsVersionAvailable\r\n");
            return true;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveVersionString( 
            /* [annotation][unique][out][string] */ 
            PWSTR pVersion,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwVersionLength) {
            printf("RetrieveVersionString\r\n");
            return 0;
        }
};


#define __winfnc __attribute__((ms_abi))

// typedef a function-pointer type that uses MS x64 ABI
using DLLGetClassObject_t = HRESULT (__winfnc *)(void*, void*, void**);



static NTSTATUS tudor_devctrl_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, 
                                   ULONG code, void *in_buf, size_t in_size, 
                                   void *out_buf, size_t out_size, 
                                   struct winwdf_request **req) {
    
    if (LOG_LEVEL <= LOG_VERBOSE) {
        printf("[WUDF1-DEVCTRL] -> code 0x%x (size 0x%lx)\r\n", code, in_size);
    }

    // For UMDF1, we need to handle this through the queue callback mechanism
    // The actual I/O will be handled when the driver calls our queue callbacks
    
    // Store the request info for when the callback is invoked
    // This is a simplified approach - you might need a more sophisticated request tracking system
    
    if (myQueue) {
        //MyMem in(ibuf, sizeof(ibuf)), out(obuf, sizeof(obuf));
        MyMem in(in_buf, in_size), out(out_buf, out_size);
        MyRequest req(WdfRequestTypeOther, 0x442004, &out, &in);

        printf("about to ioctl: 0x%x\r\n", code);
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, code, 0, 0);
        while(!req.complete)
            usleep(20000);
    }
    
    // For now, return pending - the actual completion will happen in the callback
    return STATUS_PENDING;
}

static NTSTATUS tudor_cancel_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, struct winwdf_request *req) {
    // winwdf_cancel_request(req);
    return STATUS_SUCCESS;
}

static void tudor_cleanup_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, struct winwdf_request *req) {
    // winwdf_destroy_object((WDFOBJECT) req);
}

void print_vtable(void* obj, int N) {
    void** vtable = *reinterpret_cast<void***>(obj);
    for (int i = 0; i < N; i++) {
        printf("%d: %p\n", i, vtable[i]);
    }
    fflush(stdout);
}


bool tudor_init() {

    winmodule_register(&ntdll_module);
    winreg_set_handler(tudor_reg_handler, NULL);

    print_guid(&SYNA_CLSID);
    print_guid(&IID_IUnknown);

    tudor_adapter_dll = tudor_driver_dll = NULL;
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];
        if(!load_dll(&dll->image, dll->module.name, dll->pe_image, dll->pe_image_end - dll->pe_image)) {
            log_error("Error loading driver DLL!");
            return false;
        }
        winmodule_register(&dll->module);
        log_info("Loaded driver DLL '%s' [%ld bytes]", dll->module.name, dll->pe_image_end - dll->pe_image);

        if(dll->is_adapter) tudor_adapter_dll = dll;
        if(dll->is_driver) tudor_driver_dll = dll;
    }

    if(!tudor_adapter_dll) abort();
    if(!tudor_driver_dll) abort();

    // //Initialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Initializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_ATTACH, NULL)) {
                log_error("Error initializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
    }

    winmodule_set_cur(&tudor_driver_dll->module);

    DLLGetClassObject_t proc = (DLLGetClassObject_t) (void*) find_dll_export(&tudor_driver_dll->image, "DllGetClassObject");
    IClassFactory *fact = NULL;

    printf("Received proc: %p\n", proc);

    printf("about to create factory\r\n");
    void* a = (void*) &SYNA_CLSID;
    void* b = (void*) &IID_IUnknown;
    void** c = (void**) &fact;

    // uint32_t proc_res = call_DllGetClassObject_windows_abi((void*)proc, &SYNA_CLSID, &IID_IUnknown, c);
    HRESULT proc_res = proc(a, b, c);
    printf("done\r\n");
    printf("proc res: %d\n", proc_res);


    void* dibr = NULL;
    proc_res = proc((void*)&GUID_DEVINTERFACE_BIOMETRIC_READER, (void*)&IID_IUnknown, &dibr);
    printf("GUID_DEVINTERFACE rc = %d\n", proc_res);


    printf("about to create instance fact = %p\r\n", fact);
    if(!fact) {
        puts("SYNA_CLSID not found in DLL");
        return 0;
    }
    HRESULT res = fact->CreateInstance(NULL, &IID_IDriverEntry, (void**)&inst);

    if (res != 0) {
        printf("Failed to create instance: %d\n", res);
        // return 0;
    }

    printf("Received instance: %p\n", inst);

    HRESULT rc;

    // MyDriver *aDriver = new MyDriver();
    aDriver = new MyDriver();
    printf("about to init %p\r\n", aDriver);

    rc = inst->OnInitialize(aDriver);

    printf("OnInitialize rc = %lx\r\n", rc);
    if(rc < 0) {
        printf("Couldn't initialize\n");
        abort();
    }

    printf("Successfully initialized Driver\n");

    MyDevInit *devinit = new MyDevInit();
    printf("about to add device %p\r\n", devinit);
    rc = inst->OnDeviceAdd(aDriver, devinit);
    // printf("OnDeviceAdd rc = %lx\r\n", rc);
    // if(rc < 0) {
    //     return 0;
    // }
    printf("OnDeviceAdd finished, rc = %d\n", rc);
    fflush(stdout);


    printf("about to prepare hw\r\n");
    print_vtable(myDevice->pnphwcb, 5); 

    rc = myDevice->pnphwcb->OnPrepareHardware(myDevice);
    usleep(5000000);
    printf("OnPrepareHardware rc = %lx\r\n", rc);
    fflush(stdout);
    //
    if(rc != 0) {
        abort();
    }
    //
    usleep(1000000);
    printf("about to enter D0 state\r\n");
    rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    printf("OnD0Entry rc = %lx\r\n", rc);
    usleep(20000);


    //Query WINBIO interfaces
    winmodule_set_cur(&tudor_adapter_dll->module);

    HRESULT hres;
    if((hres = ((api_WbioQuerySensorInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQuerySensorInterface"))(&tudor_sensor_adapter)) != 0) {
        log_error("Error querying sensor interface: 0x%x!", hres);
        return false;
    }
    if((hres = ((api_WbioQueryEngineInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQueryEngineInterface"))(&tudor_engine_adapter)) != 0) {
        log_error("Error querying engine interface: 0x%x!", hres);
        return false;
    }

    printf("tudor_init finish!\n");
    return true;

}

bool tudor_shutdown() {
    //Unload the driver
    winmodule_set_cur(&tudor_driver_dll->module);

    inst->OnDeinitialize(aDriver);
    printf("======================================================\r\n");
    printf("Sleeping 10 secons....\r\n");
    printf("======================================================\r\n");
    usleep(5000);


    //Uninitialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Uninitializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_DETACH, NULL)) {
                log_error("Error uninitializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
        winmodule_unregister(&dll->module);
    }

    //Destroy driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) destroy_dll(&tudor_windrv_dlls[i].image);

    //Unregister dummy modules
    winmodule_unregister(&ntdll_module);

    return true;
}

bool device_init()
{
    // MyDevInit *devinit = new MyDevInit();
    // printf("about to add device %p\r\n", devinit);
    // HRESULT rc = inst->OnDeviceAdd(aDriver, devinit);
    // printf("OnDeviceAdd rc = %lx\r\n", rc);
    // if(rc < 0) {
    //     return false;
    // }
    //
    // goIdle = 0;
    //
    // usleep(100);
    // printf("about to prepare hw\r\n");
    // rc = myDevice->pnphwcb->OnPrepareHardware(myDevice);
    // printf("OnPrepareHardware rc = %lx\r\n", rc);
    //
    // if(rc < 0) {
    //     return false;
    // }
    //
    // usleep(100);
    // printf("about to enter D0 state\r\n");
    // rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    // printf("OnD0Entry rc = %lx\r\n", rc);
    return true;
}

bool tudor_open(struct tudor_device *device, libusb_device_handle *usb_dev, struct tudor_device_state *state)
{
    HRESULT hres;
    NTSTATUS status;

    device->state = state ? *state : (struct tudor_device_state) {0};
    device->enrolling = false;
    cant_fail_ret(pthread_mutex_init(&device->records_lock, NULL));
    device->records_head = NULL;
    device->result_records_head = device->result_records_cursor = NULL;

    device_init();

    //This is dumb, but otherwise we run into race conditions
    cant_fail(usleep(3000));

    //Initialize the pipeline
    winmodule_set_cur(&tudor_adapter_dll->module);

    log_debug("Initializing WINBIO pipeline...");
    device->pipeline = (WINBIO_PIPELINE*) malloc(sizeof(WINBIO_PIPELINE));
    if(!device->pipeline) { perror("Error allocating WINBIO pipeline"); abort(); }
    *device->pipeline = (WINBIO_PIPELINE) {0};
    device->pipeline->EngineInterface = tudor_engine_adapter;
    device->pipeline->SensorInterface = tudor_sensor_adapter;
    // device->pipeline->StorageInterface = tudor_storage_adapter;
    // device->pipeline->SensorHandle = device->winbio_file = winio_create_file(device, true, NULL, NULL, (winio_devctrl_fnc*) tudor_devctrl, (winio_cancel_fnc*) tudor_cancel, (winio_cleanup_fnc*) tudor_cleanup, NULL);
    device->pipeline->SensorHandle = device->winbio_file = winio_create_file(
        device, 
        true, 
        NULL, 
        NULL, 
        (winio_devctrl_fnc*) tudor_devctrl_wudf1,  // New function needed
        (winio_cancel_fnc*) tudor_cancel_wudf1,    // New function needed
        (winio_cleanup_fnc*) tudor_cleanup_wudf1,  // New function needed
        NULL
    );

    device->pipeline->EngineHandle = INVALID_HANDLE_VALUE;
    device->pipeline->StorageHandle = INVALID_HANDLE_VALUE;
    device->pipeline->StorageContext = device;

    log_debug("Attaching interfaces to pipeline...");
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->Attach, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->Attach, device->pipeline);
    // WINBIO_CALL_PIPELINE(tudor_storage_adapter->Attach, device->pipeline);

    log_debug("Initializing pipeline interfaces...");
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->PipelineInit, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->PipelineInit, device->pipeline);
    // WINBIO_CALL_PIPELINE(tudor_storage_adapter->PipelineInit, device->pipeline);

    //Reset the sensor
    log_debug("Resetting sensor...");
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->Reset, device->pipeline);

    //Activate the pipeline
    log_debug("Activating pipeline...");
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->Activate, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->Activate, device->pipeline);
    // WINBIO_CALL_PIPELINE(tudor_storage_adapter->Activate, device->pipeline);

    //Check the sensor status
    log_debug("Checking sensor status...");
    ULONG sensor_status = WINBIO_SENSOR_FAILURE;
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->QueryStatus, device->pipeline, &sensor_status)
    if(sensor_status != WINBIO_SENSOR_READY) {
        log_error("Sensor didn't return ready status! [status 0x%x]", status);
        return false;
    }

    return true;
}

bool tudor_close(struct tudor_device *device)
{


    return true;
}

