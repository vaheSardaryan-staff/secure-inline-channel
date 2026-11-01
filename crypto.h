/*
 * crypto.h - handshake and per-packet protection for the inline devices.
 *
 * Design
 * ------
 * - Session key agreed per run with EPHEMERAL Diffie-Hellman (ffdhe2048,
 *   RFC 7919), so a recorded session cannot be decrypted later even if the
 *   pre-shared secret leaks (forward secrecy).
 * - The DH exchange is AUTHENTICATED with a 32-byte pre-shared key (psk.hex).
 *   Each side proves it knows the PSK and saw the same two public keys, which
 *   stops an active attacker from running its own DH with each device.
 * - Data packets carry only the 16-byte GCM tag appended to the (same-length)
 *   ciphertext. The 96-bit nonce is NOT transmitted: both devices recompute it
 *   from fields they already see in the packet, so every packet still gets a
 *   unique nonce without spending a single extra byte on the wire.
 *
 *     nonce = HMAC-SHA256(nonce_master, "N" | flow | isn | seq64 | len)[0..12]
 *     aad   =               "A" | flow | isn | seq64   (authenticated headers)
 *
 *   "flow" is the connection's 4-tuple in a canonical order plus a direction
 *   bit, identical on both devices. "isn" is that direction's initial sequence
 *   number, which separates connections reusing a 4-tuple. "seq64" is the TCP
 *   sequence number extended to 64 bits, so it does not repeat when the 32-bit
 *   field wraps. A TCP retransmission repeats the nonce with identical bytes,
 *   and so produces the identical packet.
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#define DH_PUB_LEN     256   /* ffdhe2048 public value, fixed width */
#define PSK_LEN        32
#define GCM_NONCE_LEN  12
#define GCM_TAG_LEN    16
#define CONFIRM_LEN    32
#define AES_KEY_LEN    32

/* One TCP flow as both devices see it: canonical 4-tuple + direction bit. */
struct flowid {
    uint8_t canon[12];   /* lo_ip|lo_port|hi_ip|hi_port, network order */
    uint8_t dir;         /* 0 = lo->hi, 1 = hi->lo */
    uint32_t isn;        /* initial sequence number of this direction */
};

/* Our ephemeral DH key for one run. */
struct handshake {
    EVP_PKEY *key;
    uint8_t   pub[DH_PUB_LEN];
};

/* Everything needed to protect/unprotect packets after a successful handshake. */
struct session {
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
    EVP_MAC        *mac;                 /* HMAC provider */
    uint8_t         nonce_master[32];
    uint8_t         confirm[CONFIRM_LEN];      /* handshake value we send */
    uint8_t         confirm_peer[CONFIRM_LEN]; /* handshake value we expect */
    int             ready;
};

int  crypto_global_init(void);

/* Generate our ephemeral DH keypair; fills hs->pub. Returns 0 on success. */
int  handshake_init(struct handshake *hs);
void handshake_free(struct handshake *hs);

/* Combine our key with the peer's public value and the PSK into a session.
 * Fills s (including s->confirm, the value to send, and s->confirm_peer, the
 * value to expect). Returns 0 on success, -1 on failure or if peer_pub is our
 * own public value. */
int  session_derive(const struct handshake *hs, const uint8_t peer_pub[DH_PUB_LEN],
                    const uint8_t psk[PSK_LEN], struct session *s);
void session_free(struct session *s);

/* Encrypt len plaintext bytes in place-safe buffers; writes ciphertext (len
 * bytes) and the 16-byte tag. Returns 0 on success. */
int  session_seal(struct session *s, const struct flowid *f, uint64_t seq,
                  const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[GCM_TAG_LEN]);

/* Verify the tag and decrypt. Returns 0 on success, -1 if authentication
 * fails (tampered, wrong key, or replay into the wrong position). */
int  session_open(struct session *s, const struct flowid *f, uint64_t seq,
                  const uint8_t *ct, size_t len, const uint8_t tag[GCM_TAG_LEN],
                  uint8_t *pt);

/* Extend a 32-bit TCP sequence number to 64 bits: the value closest to high,
 * the largest extended sequence seen so far. Tolerates reordering of up to
 * 2 GiB, so both devices agree even if packets arrive out of order. */
uint64_t seq_extend(uint64_t high, uint32_t seq);

/* Load a 64-hex-char PSK from a file into psk[32]. Returns 0 on success. */
int  load_psk(const char *path, uint8_t psk[PSK_LEN]);

#endif /* CRYPTO_H */
