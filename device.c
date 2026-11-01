/*
 * device.c - inline encrypting device. Same binary on Device1 and Device2.
 *
 *   ./device [-v] <plain_if> <cipher_if> <psk_file>
 *
 *   Device1:  ./device d1-pc d1-net psk.hex
 *   Device2:  ./device d2-pc d2-net psk.hex
 *
 *   plain_if  = interface facing the local PC    (clear text)
 *   cipher_if = interface facing the peer device (protected)
 *   psk_file  = 64 hex chars, same file on both devices (authenticates the
 *               handshake only; the data key comes from ephemeral DH)
 *
 * Two phases:
 *
 *  1. Handshake. On startup each device runs an ephemeral Diffie-Hellman
 *     exchange with its peer over small control frames (a private EtherType,
 *     never forwarded to the PCs), authenticated with the PSK. No TCP data is
 *     forwarded until the shared session key is confirmed on both sides.
 *
 *  2. Protected forwarding (bump in the wire, no IP of its own):
 *       plain  -> cipher : encrypt the TCP payload, append the 16-byte GCM tag
 *       cipher -> plain  : verify the tag, decrypt, drop the tag
 *     Only the TCP payload changes. IP/TCP headers are preserved; IP total
 *     length and both checksums are recomputed. ARP, ICMP and payload-free TCP
 *     (SYN/ACK) pass through untouched. No UDP wrapper, no extra header: on the
 *     link between the devices each packet is still an ordinary TCP/IP packet,
 *     just with an encrypted payload and 16 bytes of tag.
 *
 *   | Eth | IP | TCP | encrypted payload (same length) | TAG(16) |
 *
 * The 96-bit GCM nonce is never sent: both devices recompute it from the
 * packet's flow, sequence number and length, so it is unique for every packet
 * while costing zero bytes on the wire (see crypto.c).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "crypto.h"

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

/* ---- constants --------------------------------------------------------- */
#define ETH_HLEN_        14
#define IP_MIN_HLEN      20
#define TCP_MIN_HLEN     20
#define ETH_P_HS         0x88B5   /* local-experimental EtherType for handshake */
#define HS_VERSION       1
#define HS_HELLO         1        /* body: DH public value (DH_PUB_LEN) */
#define HS_CONFIRM       2        /* body: CONFIRM_LEN-byte confirmation */
#define HS_RESEND_MS     150
#define HS_WARN_TRIES    100
#define MAX_FRAME        65536
#define BUF_SIZE         (MAX_FRAME + GCM_TAG_LEN)
#define RX_BUDGET        256
#define MSS_HEADROOM     76       /* 20 IP + max 40 TCP options + 16 tag */

/* ---- state ------------------------------------------------------------- */
struct port {
    const char *name;
    int ifindex;
    int mtu;
    int fd;
    uint8_t mac[ETH_ALEN];
};

struct stats {
    unsigned long encrypted, decrypted, passthrough;
    unsigned long fwd_p2c, fwd_c2p, mss_clamped;
    unsigned long drop_not_ready, drop_auth_fail, drop_bad_format;
    unsigned long drop_bad_csum, drop_oversize, drop_send_fail, drop_crypto_err;
};

struct device {
    struct port plain;
    struct port cipher;
    uint8_t psk[PSK_LEN];
    struct handshake hs;
    struct session   sess;
    int derived;         /* we have combined keys and can send CONFIRM */
    int have_peer_pub;
    uint8_t peer_pub[DH_PUB_LEN];
    int tries;
    struct timespec last_send;
    uint16_t max_mss;
    int verbose;
    struct stats st;
};

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static long ms_since(const struct timespec *t)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t->tv_sec) * 1000 + (now.tv_nsec - t->tv_nsec) / 1000000;
}

/* ---- byte helpers ------------------------------------------------------ */
static inline uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t get32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* ---- Internet checksum ------------------------------------------------- */
static uint32_t csum_add(const uint8_t *d, size_t n, uint32_t sum)
{
    while (n > 1) { sum += ((uint32_t)d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) sum += (uint32_t)d[0] << 8;
    return sum;
}
static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}
static uint16_t tcp_checksum(const uint8_t *ip, const uint8_t *tcp, size_t tcp_len)
{
    uint8_t ph[12];
    memcpy(ph, ip + 12, 8);
    ph[8] = 0; ph[9] = IPPROTO_TCP;
    put16(ph + 10, (uint16_t)tcp_len);
    return csum_fold(csum_add(tcp, tcp_len, csum_add(ph, sizeof ph, 0)));
}

/* ---- packet parsing ---------------------------------------------------- */
struct pkt {
    uint8_t *ip; size_t ihl, tot_len;
    uint8_t *tcp; size_t thl;
    uint8_t *payload; size_t plen;
};

static int parse_ipv4_tcp(uint8_t *f, size_t len, struct pkt *p)
{
    if (len < ETH_HLEN_ + IP_MIN_HLEN) return 0;
    if (get16(f + 12) != ETH_P_IP) return 0;
    uint8_t *ip = f + ETH_HLEN_;
    if ((ip[0] >> 4) != 4) return 0;
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
    size_t tot = get16(ip + 2);
    if (ihl < IP_MIN_HLEN || tot < ihl || ETH_HLEN_ + tot > len) return 0;
    if (ip[9] != IPPROTO_TCP) return 0;
    if (get16(ip + 6) & 0x3FFF) return 0;              /* fragmented */
    uint8_t *tcp = ip + ihl;
    if (tot - ihl < TCP_MIN_HLEN) return 0;
    size_t thl = (size_t)(tcp[12] >> 4) * 4;
    if (thl < TCP_MIN_HLEN || ihl + thl > tot) return 0;
    p->ip = ip; p->ihl = ihl; p->tot_len = tot;
    p->tcp = tcp; p->thl = thl;
    p->payload = tcp + thl; p->plen = tot - ihl - thl;
    return 1;
}

static int ip_csum_ok(const struct pkt *p)
{ return csum_fold(csum_add(p->ip, p->ihl, 0)) == 0; }
static int tcp_csum_ok(const struct pkt *p)
{ return tcp_checksum(p->ip, p->tcp, p->tot_len - p->ihl) == 0; }

static void fix_headers(struct pkt *p)
{
    put16(p->ip + 2, (uint16_t)p->tot_len);
    put16(p->ip + 10, 0);
    put16(p->ip + 10, csum_fold(csum_add(p->ip, p->ihl, 0)));
    put16(p->tcp + 16, 0);
    put16(p->tcp + 16, tcp_checksum(p->ip, p->tcp, p->tot_len - p->ihl));
}

/* Canonical flow id + direction, identical on both devices. */
static void flow_of(const struct pkt *p, struct flowid *f)
{
    uint8_t a[6], b[6];
    memcpy(a, p->ip + 12, 4); memcpy(a + 4, p->tcp, 2);       /* src ip|port */
    memcpy(b, p->ip + 16, 4); memcpy(b + 4, p->tcp + 2, 2);   /* dst ip|port */
    if (memcmp(a, b, 6) <= 0) {
        memcpy(f->canon, a, 6); memcpy(f->canon + 6, b, 6); f->dir = 0;
    } else {
        memcpy(f->canon, b, 6); memcpy(f->canon + 6, a, 6); f->dir = 1;
    }
}

/* Lower the MSS option in SYN packets as a safety net. */
static int clamp_mss(struct pkt *p, uint16_t max_mss)
{
    if (!(p->tcp[13] & 0x02)) return 0;
    uint8_t *o = p->tcp;
    size_t i = TCP_MIN_HLEN;
    int changed = 0;
    while (i < p->thl) {
        uint8_t kind = o[i];
        if (kind == 0) break;
        if (kind == 1) { i++; continue; }
        if (i + 1 >= p->thl) break;
        uint8_t olen = o[i + 1];
        if (olen < 2 || i + olen > p->thl) break;
        if (kind == 2 && olen == 4 && get16(o + i + 2) > max_mss) {
            put16(o + i + 2, max_mss);
            changed = 1;
        }
        i += olen;
    }
    return changed;
}

/* ---- handshake --------------------------------------------------------- */
static uint8_t g_hs_frame[ETH_HLEN_ + 4 + DH_PUB_LEN];

static int hs_send(struct device *d, uint8_t type, const uint8_t *body, size_t blen)
{
    uint8_t *f = g_hs_frame;
    memset(f, 0xFF, ETH_ALEN);                          /* broadcast to the peer */
    memcpy(f + 6, d->cipher.mac, ETH_ALEN);
    put16(f + 12, ETH_P_HS);
    f[ETH_HLEN_ + 0] = HS_VERSION;
    f[ETH_HLEN_ + 1] = type;
    put16(f + ETH_HLEN_ + 2, (uint16_t)blen);
    memcpy(f + ETH_HLEN_ + 4, body, blen);
    size_t total = ETH_HLEN_ + 4 + blen;

    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_ifindex = d->cipher.ifindex;
    to.sll_halen = ETH_ALEN;
    memset(to.sll_addr, 0xFF, ETH_ALEN);
    if (sendto(d->cipher.fd, f, total, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)total)
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &d->last_send);
    return 0;
}

/* Combine keys once we have the peer's public value. */
static void hs_derive_if_possible(struct device *d)
{
    if (d->derived || !d->have_peer_pub)
        return;
    if (session_derive(&d->hs, d->peer_pub, d->psk, &d->sess) != 0) {
        fprintf(stderr, "device: session derivation failed\n");
        session_free(&d->sess);
        d->have_peer_pub = 0;            /* wait for a usable HELLO */
        return;
    }
    d->sess.ready = 0;   /* keys exist; forward only after the peer confirms */
    d->derived = 1;
}

/* Send what we can right now: always our HELLO (the peer may still lack our
 * public key), plus our CONFIRM once we have derived. */
static void hs_send_stage(struct device *d)
{
    hs_send(d, HS_HELLO, d->hs.pub, DH_PUB_LEN);
    if (d->derived)
        hs_send(d, HS_CONFIRM, d->sess.confirm, CONFIRM_LEN);
}

/* Periodic retransmit until the session is up. */
static void hs_retry(struct device *d)
{
    if (d->sess.ready || ms_since(&d->last_send) < HS_RESEND_MS)
        return;
    /* Keep going after the warning: the peer may simply start later. */
    if (++d->tries == HS_WARN_TRIES)
        fprintf(stderr, "device: handshake not completing yet - peer down or PSK mismatch?\n");
    hs_send_stage(d);
}

static void hs_handle(struct device *d, const uint8_t *f, size_t len)
{
    if (len < ETH_HLEN_ + 4) return;
    const uint8_t *b = f + ETH_HLEN_;
    if (b[0] != HS_VERSION) return;
    uint8_t type = b[1];
    size_t blen = get16(b + 2);
    const uint8_t *body = b + 4;
    if (ETH_HLEN_ + 4 + blen > len) return;

    if (type == HS_HELLO && blen == DH_PUB_LEN) {
        /* Until the session is confirmed the newest HELLO wins, so a bogus one
         * or a restarted peer cannot lock us out for the rest of the run. */
        if (!d->sess.ready
            && (!d->have_peer_pub || memcmp(d->peer_pub, body, DH_PUB_LEN) != 0)) {
            if (d->derived) {
                session_free(&d->sess);
                d->derived = 0;
            }
            memcpy(d->peer_pub, body, DH_PUB_LEN);
            d->have_peer_pub = 1;
            hs_derive_if_possible(d);
        }
        if (d->derived)                      /* peer may still need our CONFIRM */
            hs_send(d, HS_CONFIRM, d->sess.confirm, CONFIRM_LEN);
    } else if (type == HS_CONFIRM && blen == CONFIRM_LEN) {
        if (d->derived && !d->sess.ready) {
            if (CRYPTO_memcmp(body, d->sess.confirm_peer, CONFIRM_LEN) == 0) {
                d->sess.ready = 1;
                /* Answer once, on this transition only. Replying to every
                 * CONFIRM would make two ready devices bounce frames forever. */
                hs_send(d, HS_CONFIRM, d->sess.confirm, CONFIRM_LEN);
                fprintf(stderr, "device: secure session established (ephemeral DH, AES-256-GCM)\n");
            } else {
                fprintf(stderr, "device: handshake confirmation MISMATCH - "
                                "wrong PSK or tampered exchange, refusing to forward\n");
            }
        }
    }
}

/* ---- data path --------------------------------------------------------- */
enum verdict { FORWARD, DROP };
static uint8_t g_scratch[BUF_SIZE];

static enum verdict do_encrypt(struct device *d, struct pkt *p)
{
    size_t new_tot = p->tot_len + GCM_TAG_LEN;
    if (new_tot > (size_t)d->cipher.mtu) {
        d->st.drop_oversize++;
        if (d->verbose)
            fprintf(stderr, "drop: %zu + tag exceeds cipher MTU %d\n", p->tot_len, d->cipher.mtu);
        return DROP;
    }
    struct flowid f; flow_of(p, &f);
    uint32_t seq = get32(p->tcp + 4);
    uint8_t tag[GCM_TAG_LEN];
    if (session_seal(&d->sess, &f, seq, p->payload, p->plen, g_scratch, tag) != 0) {
        d->st.drop_crypto_err++;
        return DROP;
    }
    memcpy(p->payload, g_scratch, p->plen);
    memcpy(p->payload + p->plen, tag, GCM_TAG_LEN);
    p->plen += GCM_TAG_LEN;
    p->tot_len = new_tot;
    d->st.encrypted++;
    return FORWARD;
}

static enum verdict do_decrypt(struct device *d, struct pkt *p)
{
    if (p->plen < GCM_TAG_LEN + 1) {          /* need tag + >=1 data byte */
        d->st.drop_bad_format++;
        return DROP;
    }
    size_t clen = p->plen - GCM_TAG_LEN;
    const uint8_t *tag = p->payload + clen;
    struct flowid f; flow_of(p, &f);
    uint32_t seq = get32(p->tcp + 4);
    if (session_open(&d->sess, &f, seq, p->payload, clen, tag, g_scratch) != 0) {
        d->st.drop_auth_fail++;
        if (d->verbose)
            fprintf(stderr, "drop: authentication failed (tampered or wrong key)\n");
        return DROP;
    }
    memcpy(p->payload, g_scratch, clen);
    p->plen = clen;
    p->tot_len -= GCM_TAG_LEN;
    d->st.decrypted++;
    return FORWARD;
}

static enum verdict process(struct device *d, uint8_t *frame, size_t *len, int from_plain)
{
    struct pkt p;
    if (!parse_ipv4_tcp(frame, *len, &p)) {
        d->st.passthrough++;                  /* ARP, ICMP, IPv6... */
        return FORWARD;
    }
    if (!d->sess.ready) {
        d->st.drop_not_ready++;               /* no data before the session is up */
        return DROP;
    }
    if (!ip_csum_ok(&p)) {
        d->st.drop_bad_csum++;
        return DROP;
    }
    /* Clear-text side packets must have a valid TCP checksum before we touch
     * them. Encrypted-side payloads are protected by the GCM tag instead. */
    int gcm_protected = !from_plain && p.plen > 0;
    if (!gcm_protected && !tcp_csum_ok(&p)) {
        d->st.drop_bad_csum++;
        return DROP;
    }

    int modified = 0;
    if (from_plain) {
        if (clamp_mss(&p, d->max_mss)) { d->st.mss_clamped++; modified = 1; }
        if (p.plen > 0) {
            if (do_encrypt(d, &p) == DROP) return DROP;
            modified = 1;
        }
    } else {
        if (p.plen > 0) {
            if (do_decrypt(d, &p) == DROP) return DROP;
            modified = 1;
        }
        if (clamp_mss(&p, d->max_mss)) { d->st.mss_clamped++; modified = 1; }
    }

    if (!modified) {
        d->st.passthrough++;
        return FORWARD;
    }
    fix_headers(&p);
    *len = ETH_HLEN_ + p.tot_len;

    if (d->verbose) {
        char s[INET_ADDRSTRLEN], t[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, p.ip + 12, s, sizeof s);
        inet_ntop(AF_INET, p.ip + 16, t, sizeof t);
        fprintf(stderr, "%s %s:%u -> %s:%u payload=%zu\n",
                from_plain ? "ENC" : "DEC", s, get16(p.tcp), t, get16(p.tcp + 2), p.plen);
    }
    return FORWARD;
}

/* ---- raw sockets ------------------------------------------------------- */
static int open_port(struct port *pt, const char *name)
{
    pt->name = name;
    pt->fd = -1;
    pt->ifindex = (int)if_nametoindex(name);
    if (pt->ifindex == 0) {
        fprintf(stderr, "device: no interface '%s' (%s)\n", name, strerror(errno));
        return -1;
    }
    pt->fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (pt->fd < 0) {
        perror("device: socket(AF_PACKET) (are you root?)");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", name);
    if (ioctl(pt->fd, SIOCGIFMTU, &ifr) < 0) { perror("device: SIOCGIFMTU"); return -1; }
    pt->mtu = ifr.ifr_mtu;
    if (ioctl(pt->fd, SIOCGIFHWADDR, &ifr) < 0) { perror("device: SIOCGIFHWADDR"); return -1; }
    memcpy(pt->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = pt->ifindex;
    if (bind(pt->fd, (struct sockaddr *)&sll, sizeof sll) < 0) { perror("device: bind"); return -1; }

    struct packet_mreq mr;
    memset(&mr, 0, sizeof mr);
    mr.mr_ifindex = pt->ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(pt->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) {
        perror("device: promisc");
        return -1;
    }
    int one = 1;
    (void)setsockopt(pt->fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof one);
    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(pt->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    return 0;
}

static int send_frame(struct device *d, struct port *out, const uint8_t *f, size_t len)
{
    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_ifindex = out->ifindex;
    memcpy(&to.sll_protocol, f + 12, 2);
    to.sll_halen = ETH_ALEN;
    memcpy(to.sll_addr, f, ETH_ALEN);
    for (int attempt = 0; attempt < 5; attempt++) {
        ssize_t n = sendto(out->fd, f, len, 0, (struct sockaddr *)&to, sizeof to);
        if (n == (ssize_t)len) return 0;
        if (n >= 0) break;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            struct pollfd pfd = { .fd = out->fd, .events = POLLOUT };
            (void)poll(&pfd, 1, 20);
            continue;
        }
        if (d->verbose) fprintf(stderr, "send on %s: %s\n", out->name, strerror(errno));
        break;
    }
    d->st.drop_send_fail++;
    return -1;
}

static uint8_t g_frame[BUF_SIZE];

static int drain(struct device *d, struct port *in, struct port *out, int from_plain)
{
    for (int i = 0; i < RX_BUDGET; i++) {
        struct sockaddr_ll from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(in->fd, g_frame, MAX_FRAME, MSG_TRUNC,
                             (struct sockaddr *)&from, &fl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            fprintf(stderr, "device: recv on %s: %s\n", in->name, strerror(errno));
            return errno == ENETDOWN ? 0 : -1;
        }
        if (from.sll_pkttype == PACKET_OUTGOING) continue;
        if (n > MAX_FRAME) { d->st.drop_oversize++; continue; }
        size_t len = (size_t)n;

        /* Handshake control frames appear only on the cipher side and are
         * consumed here, never forwarded to the PC. */
        if (get16(g_frame + 12) == ETH_P_HS) {
            if (!from_plain) hs_handle(d, g_frame, len);
            continue;
        }

        if (process(d, g_frame, &len, from_plain) == DROP) continue;
        if (len > (size_t)out->mtu + ETH_HLEN_) {    /* offloads still on? run ethtool -K */
            d->st.drop_oversize++;
            if (d->verbose)
                fprintf(stderr, "drop: %zu-byte frame larger than %s MTU\n", len, out->name);
            continue;
        }
        if (send_frame(d, out, g_frame, len) == 0) {
            if (from_plain) d->st.fwd_p2c++; else d->st.fwd_c2p++;
        }
    }
    return 0;
}

/* ---- stats & setup ----------------------------------------------------- */
static void print_stats(const struct device *d)
{
    const struct stats *s = &d->st;
    fprintf(stderr,
        "device %s<->%s stats:\n"
        "  forwarded plain->cipher : %lu\n"
        "  forwarded cipher->plain : %lu\n"
        "  encrypted               : %lu\n"
        "  decrypted               : %lu\n"
        "  passed through as is     : %lu\n"
        "  MSS clamped             : %lu\n"
        "  dropped: session not up : %lu\n"
        "  dropped: auth failed    : %lu\n"
        "  dropped: bad format     : %lu\n"
        "  dropped: bad checksum   : %lu\n"
        "  dropped: too big        : %lu\n"
        "  dropped: send failed    : %lu\n"
        "  dropped: crypto error   : %lu\n",
        d->plain.name, d->cipher.name, s->fwd_p2c, s->fwd_c2p, s->encrypted, s->decrypted,
        s->passthrough, s->mss_clamped, s->drop_not_ready, s->drop_auth_fail,
        s->drop_bad_format, s->drop_bad_csum, s->drop_oversize, s->drop_send_fail,
        s->drop_crypto_err);
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-v] <plain_if> <cipher_if> <psk_file>\n"
                    "  plain_if   interface towards the local PC\n"
                    "  cipher_if  interface towards the peer device\n"
                    "  psk_file   64 hex chars (openssl rand -hex 32 > psk.hex)\n"
                    "  -v         log every encrypted/decrypted/dropped packet\n", prog);
}

int main(int argc, char **argv)
{
    struct device d;
    memset(&d, 0, sizeof d);
    d.plain.fd = d.cipher.fd = -1;

    int opt;
    while ((opt = getopt(argc, argv, "vh")) != -1) {
        if (opt == 'v') d.verbose = 1;
        else { usage(argv[0]); return opt == 'h' ? 0 : 2; }
    }
    if (argc - optind != 3) { usage(argv[0]); return 2; }
    const char *plain_if = argv[optind], *cipher_if = argv[optind + 1];
    const char *psk_path = argv[optind + 2];
    if (strcmp(plain_if, cipher_if) == 0) {
        fprintf(stderr, "device: the two interfaces must be different\n");
        return 2;
    }

    if (crypto_global_init() != 0) {
        fprintf(stderr, "device: OpenSSL init failed\n");
        return 1;
    }
    if (load_psk(psk_path, d.psk) != 0)
        return 1;
    if (handshake_init(&d.hs) != 0) {
        fprintf(stderr, "device: DH key generation failed\n");
        return 1;
    }

    int rc = 1;
    if (open_port(&d.plain, plain_if) != 0 || open_port(&d.cipher, cipher_if) != 0)
        goto out;

    int m1 = d.plain.mtu - IP_MIN_HLEN - TCP_MIN_HLEN;
    int m2 = d.cipher.mtu - MSS_HEADROOM;
    int max_mss = m1 < m2 ? m1 : m2;
    if (max_mss < 536) {
        fprintf(stderr, "device: MTU too small\n");
        goto out;
    }
    d.max_mss = (uint16_t)max_mss;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stderr, "device: plain=%s(mtu %d) cipher=%s(mtu %d) max MSS %u; starting handshake...\n",
            d.plain.name, d.plain.mtu, d.cipher.name, d.cipher.mtu, d.max_mss);

    hs_send_stage(&d);   /* send our first HELLO (+CONFIRM once derived) */

    struct pollfd pfd[2] = {
        { .fd = d.plain.fd,  .events = POLLIN },
        { .fd = d.cipher.fd, .events = POLLIN },
    };
    rc = 0;
    while (!g_stop) {
        int r = poll(pfd, 2, HS_RESEND_MS);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("device: poll");
            rc = 1;
            break;
        }
        if ((pfd[0].revents | pfd[1].revents) & POLLNVAL) {
            fprintf(stderr, "device: socket closed unexpectedly\n");
            rc = 1;
            break;
        }
        if (pfd[1].revents & (POLLIN | POLLERR))
            if (drain(&d, &d.cipher, &d.plain, 0) != 0) { rc = 1; break; }
        if (pfd[0].revents & (POLLIN | POLLERR))
            if (drain(&d, &d.plain, &d.cipher, 1) != 0) { rc = 1; break; }
        if (!d.sess.ready)
            hs_retry(&d);
    }
    print_stats(&d);

out:
    if (d.plain.fd >= 0) close(d.plain.fd);
    if (d.cipher.fd >= 0) close(d.cipher.fd);
    session_free(&d.sess);
    handshake_free(&d.hs);
    OPENSSL_cleanse(d.psk, sizeof d.psk);
    return rc;
}
