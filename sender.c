/*
 * sender.c - runs on PC1.
 *
 *   ./sender <receiver_ip> <port> <file>
 *   ./sender 10.20.20.2 5000 file
 *
 * Opens a normal TCP connection (AF_INET, SOCK_STREAM), sends a small header
 * (magic + file size) and then the file, and waits for the receiver to confirm
 * it saved everything.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>

#include "common.h"

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <receiver_ip> <port> <file>\n", argv[0]);
        return 2;
    }

    const char *ip_str = argv[1];
    const char *path = argv[3];
    uint16_t port;
    if (parse_port(argv[2], &port) != 0) {
        fprintf(stderr, "sender: invalid port '%s'\n", argv[2]);
        return 2;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);                 /* 2-byte number -> network order */
    if (inet_pton(AF_INET, ip_str, &dst.sin_addr) != 1) {
        fprintf(stderr, "sender: invalid IPv4 address '%s'\n", ip_str);
        return 2;
    }

    int file_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        perror("sender: open file");
        return 1;
    }
    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        perror("sender: fstat");
        close(file_fd);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "sender: '%s' is not a regular file\n", path);
        close(file_fd);
        return 1;
    }
    uint64_t file_size = (uint64_t)st.st_size;

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        perror("sender: socket");
        close(file_fd);
        return 1;
    }

    /* Keep each TCP segment small enough that the device can add its 16-byte
     * GCM tag without going over the 1500-byte MTU.
     * Must be set before connect() so it goes into the SYN. */
    int mss = XFR_TCP_MSS;
    if (setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof mss) < 0)
        perror("sender: warning: TCP_MAXSEG");

    if (set_io_timeouts(sock, IO_TIMEOUT_SEC) < 0)
        perror("sender: warning: timeouts");

    if (connect(sock, (struct sockaddr *)&dst, sizeof dst) < 0) {
        perror("sender: connect");
        close(sock);
        close(file_fd);
        return 1;
    }

    uint8_t hdr[XFR_HDR_LEN];
    memcpy(hdr, XFR_MAGIC, XFR_MAGIC_LEN);
    put_be64(hdr + XFR_MAGIC_LEN, file_size);   /* 8-byte number -> network order */
    if (send_all(sock, hdr, sizeof hdr) < 0) {
        perror("sender: send header");
        goto fail;
    }

    static uint8_t buf[CHUNK_SIZE];
    uint64_t sent = 0;
    for (;;) {
        ssize_t n = read(file_fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("sender: read file");
            goto fail;
        }
        if (n == 0)
            break;
        if (send_all(sock, buf, (size_t)n) < 0) {
            perror("sender: send data");
            goto fail;
        }
        sent += (uint64_t)n;
    }

    if (sent != file_size) {
        fprintf(stderr, "sender: file changed while sending (%llu of %llu bytes)\n",
                (unsigned long long)sent, (unsigned long long)file_size);
        goto fail;
    }

    /* Tell the receiver we're done writing, then wait for its status byte. */
    if (shutdown(sock, SHUT_WR) < 0)
        perror("sender: warning: shutdown");

    uint8_t status;
    int r = recv_all(sock, &status, 1);
    if (r != 0) {
        if (r < 0)
            perror("sender: waiting for confirmation");
        else
            fprintf(stderr, "sender: receiver closed without confirming\n");
        goto fail;
    }
    if (status != XFR_STATUS_OK) {
        fprintf(stderr, "sender: receiver reported an error (status %u)\n", status);
        goto fail;
    }

    printf("sender: sent %llu bytes to %s:%u, receiver confirmed\n",
           (unsigned long long)sent, ip_str, port);
    close(sock);
    close(file_fd);
    return 0;

fail:
    close(sock);
    close(file_fd);
    return 1;
}
