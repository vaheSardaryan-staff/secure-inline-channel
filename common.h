/*
 * common.h - helpers shared by sender.c and receiver.c
 *
 * Wire protocol between sender and receiver (on top of TCP):
 *
 *   sender -> receiver : MAGIC (4 bytes "XFR1") | FILE_SIZE (8 bytes, big-endian) | file bytes
 *   receiver -> sender : 1 status byte (0 = file fully received and saved)
 *
 * The size header lets the receiver detect a truncated transfer, and the
 * status byte lets the sender know the file really landed on disk.
 */
#ifndef COMMON_H
#define COMMON_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define XFR_MAGIC      "XFR1"
#define XFR_MAGIC_LEN  4
#define XFR_HDR_LEN    (XFR_MAGIC_LEN + 8)
#define XFR_STATUS_OK  0x00
#define XFR_STATUS_ERR 0x01

#define CHUNK_SIZE     (64 * 1024)  /* application read/write chunk */
#define XFR_TCP_MSS        1400         /* kept well under cipher MTU 1500 - 20 - 20 - 16 (tag) */
#define IO_TIMEOUT_SEC 60           /* give up if the peer goes silent this long */

/* Parse a TCP port 1..65535. Returns 0 on success. */
static inline int parse_port(const char *s, uint16_t *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

/* 64-bit host value -> 8 bytes big-endian (network order), byte by byte so it
 * is correct on any CPU. htons()/htonl() only cover 16 and 32 bits. */
static inline void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static inline uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/* send() can write fewer bytes than asked: loop until everything is out.
 * MSG_NOSIGNAL: a closed peer gives EPIPE instead of killing us with SIGPIPE. */
static inline int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* recv() can return fewer bytes than asked: loop until exactly len bytes.
 * Returns 0 on success, 1 if the peer closed early, -1 on error. */
static inline int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return 1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* write() to a file can also be partial. */
static inline int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static inline int set_io_timeouts(int fd, int seconds)
{
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
        return -1;
    return 0;
}

#endif /* COMMON_H */
