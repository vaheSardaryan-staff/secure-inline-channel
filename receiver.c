/*
 * receiver.c - runs on PC2.
 *
 *   ./receiver <port> <output_file>
 *   ./receiver 5000 out
 *
 * Waits for one TCP connection, receives the file and saves it. Data goes to
 * "<output_file>.part" first and is renamed only when every byte has arrived,
 * so a broken transfer never leaves a half-written file under the final name.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>

#include "common.h"

static void reply_status(int sock, uint8_t status)
{
    (void)send_all(sock, &status, 1);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <port> <output_file>\n", argv[0]);
        return 2;
    }

    uint16_t port;
    if (parse_port(argv[1], &port) != 0) {
        fprintf(stderr, "receiver: invalid port '%s'\n", argv[1]);
        return 2;
    }
    const char *out_path = argv[2];

    char part_path[PATH_MAX];
    int pl = snprintf(part_path, sizeof part_path, "%s.part", out_path);
    if (pl < 0 || (size_t)pl >= sizeof part_path) {
        fprintf(stderr, "receiver: output path too long\n");
        return 2;
    }

    int lsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lsock < 0) {
        perror("receiver: socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0)
        perror("receiver: warning: SO_REUSEADDR");

    /* Advertise MSS 1400 in our SYN-ACK too (inherited by the accepted socket). */
    int mss = XFR_TCP_MSS;
    if (setsockopt(lsock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof mss) < 0)
        perror("receiver: warning: TCP_MAXSEG");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);   /* 4-byte number -> htonl */
    addr.sin_port = htons(port);                /* 2-byte number -> htons */

    if (bind(lsock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("receiver: bind");
        close(lsock);
        return 1;
    }
    if (listen(lsock, 1) < 0) {
        perror("receiver: listen");
        close(lsock);
        return 1;
    }

    printf("receiver: listening on port %u\n", port);
    fflush(stdout);

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof peer;
    int sock;
    do {
        sock = accept4(lsock, (struct sockaddr *)&peer, &peer_len, SOCK_CLOEXEC);
    } while (sock < 0 && errno == EINTR);
    close(lsock);   /* one transfer only */
    if (sock < 0) {
        perror("receiver: accept");
        return 1;
    }

    char peer_ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof peer_ip);
    printf("receiver: connection from %s:%u\n", peer_ip, ntohs(peer.sin_port));
    fflush(stdout);

    if (set_io_timeouts(sock, IO_TIMEOUT_SEC) < 0)
        perror("receiver: warning: timeouts");

    uint8_t hdr[XFR_HDR_LEN];
    int r = recv_all(sock, hdr, sizeof hdr);
    if (r != 0) {
        fprintf(stderr, "receiver: failed to read header (%s)\n",
                r < 0 ? strerror(errno) : "connection closed");
        close(sock);
        return 1;
    }
    if (memcmp(hdr, XFR_MAGIC, XFR_MAGIC_LEN) != 0) {
        fprintf(stderr, "receiver: bad header, not our sender?\n");
        reply_status(sock, XFR_STATUS_ERR);
        close(sock);
        return 1;
    }
    uint64_t expected = get_be64(hdr + XFR_MAGIC_LEN);

    int out_fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out_fd < 0) {
        perror("receiver: open output");
        reply_status(sock, XFR_STATUS_ERR);
        close(sock);
        return 1;
    }

    static uint8_t buf[CHUNK_SIZE];
    uint64_t got = 0;
    int ok = 1;
    while (got < expected) {
        size_t want = sizeof buf;
        if (expected - got < want)
            want = (size_t)(expected - got);
        ssize_t n = recv(sock, buf, want, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("receiver: recv");
            ok = 0;
            break;
        }
        if (n == 0) {
            fprintf(stderr, "receiver: sender closed early (%llu of %llu bytes)\n",
                    (unsigned long long)got, (unsigned long long)expected);
            ok = 0;
            break;
        }
        if (write_all(out_fd, buf, (size_t)n) < 0) {
            perror("receiver: write output");
            ok = 0;
            break;
        }
        got += (uint64_t)n;
    }

    /* Make sure the data is on disk before claiming success. */
    if (ok && fsync(out_fd) < 0) {
        perror("receiver: fsync");
        ok = 0;
    }
    if (close(out_fd) < 0) {
        perror("receiver: close output");
        ok = 0;
    }
    if (ok && rename(part_path, out_path) < 0) {
        perror("receiver: rename");
        ok = 0;
    }
    if (!ok)
        unlink(part_path);

    reply_status(sock, ok ? XFR_STATUS_OK : XFR_STATUS_ERR);
    close(sock);

    if (!ok)
        return 1;
    printf("receiver: saved %llu bytes to %s\n", (unsigned long long)got, out_path);
    return 0;
}
