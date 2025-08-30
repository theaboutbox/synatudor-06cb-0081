#include "internal.h"

typedef struct _SLIST_ENTRY {
    struct _SLIST_ENTRY *Next;
} SLIST_ENTRY;

typedef union {
    struct {
        ULONGLONG Alignment;
        ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {
        SLIST_ENTRY *head;
    };
} SLIST_HEADER;

__winfnc void InitializeSListHead(SLIST_HEADER *header) {
    TRACE();
    header->head = NULL;
}
WINAPI(InitializeSListHead)

__winfnc SLIST_ENTRY *InterlockedFlushSList(SLIST_HEADER *header) {
    TRACE();
    SLIST_ENTRY *head = header->head;
    header->head = NULL;
    return head;
}
WINAPI(InterlockedFlushSList)
