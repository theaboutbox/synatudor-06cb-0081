#include <unistd.h>
#include <sys/socket.h>
#include <tudor/log.h>
#include "ipc.h"
#include "handler.h"

enum ipc_msg_type ipc_peek_msg(int sock) {
    enum ipc_msg_type msg_type = IPC_MSG_ACK;

    struct iovec iov = {
        .iov_base = &msg_type,
        .iov_len = sizeof(msg_type)
    };

    struct msghdr msg_hdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0
    };

    ssize_t peeked;
    cant_fail(peeked = recvmsg(sock, &msg_hdr, MSG_PEEK));
    if(peeked != (ssize_t) sizeof(msg_type)) {
        log_error("Truncated IPC message header: 0x%lx bytes", (unsigned long) peeked);
        abort();
    }

    return msg_type;
}

size_t ipc_recv_msg(int sock, void *buf, enum ipc_msg_type type, size_t min_sz, size_t max_sz, int *fd) {
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = max_sz
    };

    /* Control buffer sized for exactly one SCM_RIGHTS descriptor; the union
     * keeps it aligned for struct cmsghdr as recvmsg(2) requires. */
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg = {0};

    struct msghdr msg_hdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg.buf,
        .msg_controllen = sizeof(cmsg.buf)
    };

    ssize_t msg_size;
    cant_fail(msg_size = recvmsg(sock, &msg_hdr, 0));

    if(msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        log_error("Truncated IPC message: 0x%lx bytes received (max 0x%lx)", (unsigned long) msg_size, (unsigned long) max_sz);
        abort();
    }

    if(msg_size < min_sz || max_sz < msg_size) {
        log_error("Invalid IPC message size: 0x%lx (min 0x%lx, max 0x%lx)", msg_size, min_sz, max_sz);
        abort();
    }

    if(*((enum ipc_msg_type*) buf) != type) {
        log_error("Unexpected IPC message type: 0x%x (expected 0x%x)", *((enum ipc_msg_type*) buf), type);
        abort();
    }

    //Transfer FD
    if(msg_hdr.msg_controllen > 0) {
        struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg_hdr);
        if((msg_hdr.msg_flags & MSG_CTRUNC) || msg_hdr.msg_controllen != sizeof(cmsg.buf) || !hdr || hdr->cmsg_len != CMSG_LEN(sizeof(int)) || hdr->cmsg_level != SOL_SOCKET || hdr->cmsg_type != SCM_RIGHTS) {
            log_error("Invalid IPC control message");
            abort();
        }

        int recv_fd;
        memcpy(&recv_fd, CMSG_DATA(hdr), sizeof(recv_fd));
        if(fd) *fd = recv_fd;
        else cant_fail(close(recv_fd));
    } else if(fd) *fd = -1;

    return msg_size;
}

void ipc_send_msg(int sock, void *buf, size_t size) {
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = size
    };

    struct msghdr msg_hdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0
    };

    cant_fail(sendmsg(sock, &msg_hdr, 0));
}