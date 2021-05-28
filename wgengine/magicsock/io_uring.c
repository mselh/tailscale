#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#define LISTEN_PORT 8976

#define QUEUE_DEPTH 1
#define BLOCK_SZ    2048

typedef struct io_uring go_uring;

/*
 * Output a string of characters of len length to stdout.
 * We use buffered output here to be efficient,
 * since we need to output character-by-character.
 * */
static void output_to_console(const char *buf, int len) {
    while (len--) {
        fputc(*buf++, stdout);
    }
}

/*
 * Wait for a completion to be available, fetch the data from
 * the readv operation and print it to the console.
 * */
static int receive_into(struct io_uring *ring, char *buf, char *ip, uint16_t *port) {
    struct io_uring_cqe *cqe;
again:;
    // printf("receive into\n");
    int ret = io_uring_wait_cqe(ring, &cqe);
    // printf("received into %d\n", ret);
    if (ret == EINTR) {
        goto again;
    }
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return -1;
    }
    if (cqe->res < 0) {
        fprintf(stderr, "Async readv failed.\n");
        return -1;
    }
    struct msghdr *mhdr = io_uring_cqe_get_data(cqe);
    int n;
    n = cqe->res;
    memcpy(buf, mhdr->msg_iov[0].iov_base, n);

    struct sockaddr_in sa;
    memcpy(&sa, mhdr->msg_name, mhdr->msg_namelen);
    memcpy(ip, &sa.sin_addr, 4);
    *port = ntohs(sa.sin_port);

    free(mhdr->msg_iov[0].iov_base);
    free(mhdr->msg_iov);
    free(mhdr->msg_name);
    free(mhdr);

    io_uring_cqe_seen(ring, cqe);
    return n;
}

/*
 * Submit the recvmsg request via liburing
 * */
static int submit_recvmsg_request(int sock, struct io_uring *ring) {
    // printf("submit_recvmsg_request\n");
    struct msghdr *mhdr = malloc(sizeof(struct msghdr));
    if (!mhdr) {
        perror("malloc(msghdr)");
        return 1;
    }

    struct iovec *iov = malloc(sizeof(struct iovec));
    if (!iov) {
        perror("malloc(iov)");
        free(iov);
        return 1;
    }

    char *buff = malloc(BLOCK_SZ);
    if (!buff) {
        perror("malloc(buff)");
        free(iov);
        free(mhdr);
        return 1;
    }

    char *sender = malloc(sizeof(struct sockaddr_in));
    if (!sender) {
        perror("malloc(sender)");
        free(iov);
        free(mhdr);
        free(buff);
        return 1;
    }

    memset(iov, 0, sizeof(*iov));
    iov->iov_base = buff;
    iov->iov_len = BLOCK_SZ;

    memset(mhdr, 0, sizeof(*mhdr));
    mhdr->msg_iov = iov;
    mhdr->msg_iovlen = 1;

    memset(sender, 0, sizeof(*sender));
    mhdr->msg_name = sender;
    mhdr->msg_namelen = sizeof(*sender);

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recvmsg(sqe, sock, mhdr, 0);
    io_uring_sqe_set_data(sqe, mhdr);
    io_uring_submit(ring);

    return 0;
}

static void initializeRing(struct io_uring *ring) {
    io_uring_queue_init(QUEUE_DEPTH, ring, 0);
}

/*
int main(int argc, char *argv[]) {

    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n",
                argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
	    perror("socket");
	    return 1;
    }

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(LISTEN_PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (const struct sockaddr*)&listen_addr, sizeof(listen_addr))) {
        perror("bind");
        return 1;
    }

    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

    while (1) {
        if (submit_recvmsg_request(sock, &ring)) {
            fputs("Error reading packet\n", stderr);
            return 1;
        }
        if (get_completion_and_print(&ring)) {
            fputs("Get completion failed\n", stderr);
            return 1;
        }
    }

    io_uring_queue_exit(&ring);
    return 0;
}
*/
