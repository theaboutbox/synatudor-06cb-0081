#include "internal.h"
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t pipes_lock = PTHREAD_MUTEX_INITIALIZER;
static struct winpipe {
    struct winpipe *prev, *next;
    char *name;
    int refcnt;

    pthread_mutex_t lock;
    bool dying;

    int num_listeners;
    pthread_cond_t listen_cond;
} *pipes_head;

static NTSTATUS pipe_read(struct winpipe *pipe, OVERLAPPED *ovlp, void *buf, size_t *buf_size, void **op_ctx) {
    return WINERR_SET_CODE;
}

static NTSTATUS pipe_write(struct winpipe *pipe, OVERLAPPED *ovlp, const void *buf, size_t *buf_size, void **op_ctx) {
    return WINERR_SET_CODE;
}

static void pipe_destroy(struct winpipe *pipe) {
    cant_fail_ret(pthread_mutex_lock(&pipe->lock));
    if(--pipe->refcnt > 0) {
        cant_fail_ret(pthread_mutex_unlock(&pipe->lock));
        return;
    }
    pipe->dying = true;

    //Remove from pipes list
    cant_fail_ret(pthread_mutex_lock(&pipes_lock));
    if(pipe->prev) pipe->prev->next = pipe->next;
    else pipes_head = pipe->next;
    if(pipe->next) pipe->next->prev = pipe->prev;
    cant_fail_ret(pthread_mutex_unlock(&pipes_lock));

    //Signal server listen functions
    cant_fail_ret(pthread_cond_broadcast(&pipe->listen_cond));
    while(pipe->num_listeners > 0) cant_fail_ret(pthread_cond_wait(&pipe->listen_cond, &pipe->lock));

    //Free memory
    cant_fail_ret(pthread_cond_destroy(&pipe->listen_cond));
    cant_fail_ret(pthread_mutex_unlock(&pipe->lock));
    cant_fail_ret(pthread_mutex_destroy(&pipe->lock));

    free(pipe->name);
    free(pipe);    
}

__winfnc HANDLE CreateNamedPipeW(const char16_t *name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_buf_size, DWORD in_buf_size, DWORD default_timeout, void *security_attrs) {
    TRACE();
    //Create the pipe
    struct winpipe *pipe = (struct winpipe*) malloc(sizeof(struct winpipe));
    if(!pipe) { winerr_set_errno(); return NULL; }
    pipe->name = winstr_to_str(name);
    pipe->refcnt = 1;

    cant_fail_ret(pthread_mutex_init(&pipe->lock, NULL));
    pipe->dying = false;

    pipe->num_listeners = 0;
    cant_fail_ret(pthread_cond_init(&pipe->listen_cond, NULL));

    //Add to pipes list
    cant_fail_ret(pthread_mutex_lock(&pipes_lock));
    pipe->prev = NULL;
    pipe->next = pipes_head;
    if(pipes_head) pipes_head->prev = pipe;
    pipes_head = pipe;
    cant_fail_ret(pthread_mutex_unlock(&pipes_lock));

    return winio_create_file(pipe, (open_mode & FILE_FLAG_OVERLAPPED) != 0, (winio_read_fnc*) pipe_read, (winio_write_fnc*) pipe_write, NULL, NULL, NULL, (winio_destroy_fnc*) pipe_destroy);
}
WINAPI(CreateNamedPipeW)

__winfnc BOOL ConnectNamedPipe(HANDLE handle, OVERLAPPED *ovlp) {
    TRACE();
    struct winpipe *pipe = (struct winpipe*) winio_get_file_context(handle);

    cant_fail_ret(pthread_mutex_lock(&pipe->lock));
    while(!pipe->dying) cant_fail_ret(pthread_cond_wait(&pipe->listen_cond, &pipe->lock));
    cant_fail_ret(pthread_cond_broadcast(&pipe->listen_cond));
    cant_fail_ret(pthread_mutex_unlock(&pipe->lock));

    return FALSE;
}
WINAPI(ConnectNamedPipe)

__winfnc BOOL DisconnectNamedPipe(HANDLE handle) {
    return FALSE;
}
WINAPI(DisconnectNamedPipe)


#define CSIDL_FOLDER_MASK	0x00ff

__winfnc HRESULT SHGetFolderPathA(
	void* hwndOwner,    /* [I] owner window */
	int nFolder,       /* [I] CSIDL identifying the folder */
	HANDLE hToken,     /* [I] access token */
	DWORD dwFlags,     /* [I] which path to return */
	char* pszPath)    /* [O] converted path */
{
    TRACE();
    int folder = CSIDL_FOLDER_MASK & nFolder;
    printf("SHGetFolderPathA: %d\n", folder);
    const char *path = getenv("SYNA_TUDOR_STATE_DIR");
    if(!path || !path[0]) path = ".";
    if(!pszPath) return E_INVALIDARG;
    strcpy(pszPath, path);
    return 0;
}
WINAPI(SHGetFolderPathA)


__winfnc BOOL PathAppendA(
    char* path,
    const char* more)
{
    TRACE();

    if (!path || !more) return FALSE;

    printf("PathAppendA path: %s\n", path);
    printf("PathAppendA more: %s\n", more);

    size_t path_len = strlen(path);

    if (path_len == 0) {
        // If path is empty, just copy more
        strcpy(path, more);
        return TRUE;
    }

    // Check if path ends with '/' and more starts with '/'
    if (path[path_len - 1] != '/' && more[0] != '/') {
        path[path_len] = '/';
        path[path_len + 1] = '\0';
    } else if (path[path_len - 1] == '/' && more[0] == '/') {
        // Remove extra '/' from more
        more++;
    }

    strcat(path, more);
    printf("PathAppendA result: %s\n", path);
    return TRUE;
}
WINAPI(PathAppendA)


__winfnc BOOL PathFileExistsA(
    const char* path)
{
    TRACE();
    printf("PathExists: %s\n", path);
    if (!path) {
        return FALSE;
    }

    struct stat st;
    if (stat(path, &st) == 0) {
        return TRUE; // path exists
    } else {
        return FALSE; // stat failed → does not exist
    }
}
WINAPI(PathFileExistsA)

__winfnc BOOL CreateDirectoryA(
    const char* path, void* securityAttributes)
{
    TRACE();
    printf("CreateDirectoryA: %s\n", path);
    (void)securityAttributes; // unused in Linux implementation

    if (!path) {
        return FALSE;
    }

    if (mkdir(path, 0755) == 0) {
        return TRUE; // created successfully
    } else {
        if (errno == EEXIST) {
            return FALSE; // already exists
        }
        perror("mkdir");
        return FALSE;
    }
    return false;
}
WINAPI(CreateDirectoryA)

__winfnc HANDLE RegisterEventSourceA(
  const char* lpUNCServerName,
  const char* lpSourceName)
{
    TRACE();
    printf("RegisterEventSourceA: %s %s\n", lpUNCServerName, lpSourceName);
    return NULL;
}
WINAPI(RegisterEventSourceA)

__winfnc HANDLE CreateFileA(
    const char* path, DWORD access, DWORD share_mode, void* sec, DWORD creat, DWORD flags, void* handle)
{
    TRACE();
    printf("Path: %s\n", path);
    printf("Share mode: %d\n", share_mode);
    printf("sec: %p\n", sec);
    printf("creat: %d\n", creat);
    printf("flags: %d\n", flags);
    printf("handle: %p\n", handle);
    static const char* dummy = "ABC";
    HANDLE h = winhandle_create((void*) dummy, NULL);
    return h;
}
WINAPI(CreateFileA)
