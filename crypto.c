#include "crypto.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#define DH_GROUP "ffdhe2048"
#define AAD_LEN  (1 + 12 + 1 + 4 + 8)

/* ---- small helpers ----------------------------------------------------- */
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static EVP_MAC *g_hmac;   /* HMAC provider, fetched once */

int crypto_global_init(void)
{
    g_hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    return g_hmac ? 0 : -1;
}

/* HMAC-SHA256(key, msg) -> out (32 bytes). Returns 0 on success. */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_hmac);
    if (!ctx)
        return -1;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    size_t outl = 0;
    int ok = EVP_MAC_init(ctx, key, key_len, p) == 1
          && EVP_MAC_update(ctx, msg, msg_len) == 1
          && EVP_MAC_final(ctx, out, &outl, 32) == 1
          && outl == 32;
    EVP_MAC_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* HKDF-SHA256 extract+expand: secret -> okm bytes, bound to info. */
static int hkdf(const uint8_t *secret, size_t secret_len,
                const uint8_t *salt, size_t salt_len,
                const char *info, uint8_t *okm, size_t okm_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        return -1;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx)
        return -1;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };
    int ok = EVP_KDF_derive(ctx, okm, okm_len, p) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ---- Diffie-Hellman ---------------------------------------------------- */
static EVP_PKEY *dh_import_peer(const uint8_t *pub, size_t len)
{
    BIGNUM *bn = BN_bin2bn(pub, (int)len, NULL);
    if (!bn)
        return NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    EVP_PKEY *peer = NULL;
    if (bld
        && OSSL_PARAM_BLD_push_utf8_string(bld, "group", DH_GROUP, 0)
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn)) {
        OSSL_PARAM *prm = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (prm && ctx && EVP_PKEY_fromdata_init(ctx) == 1)
            EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, prm);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(prm);
    }
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn);
    return peer;
}

int handshake_init(struct handshake *hs)
{
    memset(hs, 0, sizeof *hs);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!ctx)
        return -1;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string("group", DH_GROUP, 0),
        OSSL_PARAM_construct_end()
    };
    int ok = EVP_PKEY_keygen_init(ctx) == 1
          && EVP_PKEY_CTX_set_params(ctx, p) == 1
          && EVP_PKEY_generate(ctx, &hs->key) == 1;
    EVP_PKEY_CTX_free(ctx);
    if (!ok)
        return -1;

    BIGNUM *bn = NULL;
    if (EVP_PKEY_get_bn_param(hs->key, OSSL_PKEY_PARAM_PUB_KEY, &bn) != 1)
        return -1;
    /* Fixed-width, left-padded: both devices must hash identical bytes. */
    int rc = BN_bn2binpad(bn, hs->pub, DH_PUB_LEN);
    BN_free(bn);
    return rc == DH_PUB_LEN ? 0 : -1;
}

void handshake_free(struct handshake *hs)
{
    if (hs->key)
        EVP_PKEY_free(hs->key);
    hs->key = NULL;
}

/* ---- session derivation ------------------------------------------------ */
static EVP_CIPHER_CTX *gcm_ctx(const uint8_t *key, int encrypt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return NULL;
    int ok = encrypt
        ? EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL)
        : EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) == 1;
    ok = ok && (encrypt
        ? EVP_EncryptInit_ex(c, NULL, NULL, key, NULL)
        : EVP_DecryptInit_ex(c, NULL, NULL, key, NULL)) == 1;
    if (!ok) {
        EVP_CIPHER_CTX_free(c);
        return NULL;
    }
    return c;
}

int session_derive(const struct handshake *hs, const uint8_t peer_pub[DH_PUB_LEN],
                   const uint8_t psk[PSK_LEN], struct session *s)
{
    memset(s, 0, sizeof *s);
    s->mac = g_hmac;

    /* Our own public value coming back is a reflection, never a real peer. */
    if (memcmp(hs->pub, peer_pub, DH_PUB_LEN) == 0)
        return -1;

    EVP_PKEY *peer = dh_import_peer(peer_pub, DH_PUB_LEN);
    if (!peer)
        return -1;

    uint8_t z[DH_PUB_LEN];
    size_t zlen = sizeof z;
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(hs->key, NULL);
    int ok = d && EVP_PKEY_derive_init(d) == 1
          && EVP_PKEY_derive_set_peer(d, peer) == 1
          && EVP_PKEY_derive(d, z, &zlen) == 1;
    EVP_PKEY_CTX_free(d);
    EVP_PKEY_free(peer);
    if (!ok)
        return -1;

    /* Transcript: the two public keys in a fixed order, so both devices hash
     * the same thing regardless of who is "first". */
    uint8_t msg[1 + 2 * DH_PUB_LEN];
    uint8_t *transcript = msg + 1;
    int we_are_low = memcmp(hs->pub, peer_pub, DH_PUB_LEN) < 0;
    if (we_are_low) {
        memcpy(transcript, hs->pub, DH_PUB_LEN);
        memcpy(transcript + DH_PUB_LEN, peer_pub, DH_PUB_LEN);
    } else {
        memcpy(transcript, peer_pub, DH_PUB_LEN);
        memcpy(transcript + DH_PUB_LEN, hs->pub, DH_PUB_LEN);
    }

    /* Key schedule: the DH secret is the input, the PSK is the salt, so both
     * the shared secret AND knowledge of the PSK are required. */
    uint8_t okm[AES_KEY_LEN + 32 + 32];
    if (hkdf(z, zlen, psk, PSK_LEN, "staffsec/v1 keys", okm, sizeof okm) != 0) {
        OPENSSL_cleanse(z, sizeof z);
        return -1;
    }
    OPENSSL_cleanse(z, sizeof z);

    s->enc = gcm_ctx(okm, 1);
    s->dec = gcm_ctx(okm + 0, 0);
    memcpy(s->nonce_master, okm + AES_KEY_LEN, 32);
    if (!s->enc || !s->dec) {
        OPENSSL_cleanse(okm, sizeof okm);
        return -1;
    }

    /* One confirmation value per role, keyed from the DH secret and the PSK and
     * covering the transcript. A substituted public key is detected, and a
     * device's own value echoed back to it does not match what it expects. */
    const uint8_t *confirm_key = okm + AES_KEY_LEN + 32;
    msg[0] = we_are_low ? 'L' : 'H';
    int rc = hmac_sha256(confirm_key, 32, msg, sizeof msg, s->confirm);
    msg[0] = we_are_low ? 'H' : 'L';
    rc |= hmac_sha256(confirm_key, 32, msg, sizeof msg, s->confirm_peer);
    OPENSSL_cleanse(okm, sizeof okm);
    if (rc != 0)
        return -1;

    s->ready = 1;
    return 0;
}

void session_free(struct session *s)
{
    if (s->enc)
        EVP_CIPHER_CTX_free(s->enc);
    if (s->dec)
        EVP_CIPHER_CTX_free(s->dec);
    s->enc = s->dec = NULL;
    OPENSSL_cleanse(s->nonce_master, sizeof s->nonce_master);
    s->ready = 0;
}

/* ---- per-packet nonce and AAD ----------------------------------------- */
uint64_t seq_extend(uint64_t high, uint32_t seq)
{
    int32_t delta = (int32_t)(seq - (uint32_t)high);
    return high + (uint64_t)(int64_t)delta;
}

/* nonce = HMAC(nonce_master, 'N' | flow | isn | seq64 | len)[0..12] */
static int derive_nonce(struct session *s, const struct flowid *f,
                        uint64_t seq, uint32_t len, uint8_t nonce[GCM_NONCE_LEN])
{
    uint8_t msg[1 + sizeof f->canon + 1 + 4 + 8 + 4];
    size_t n = 0;
    msg[n++] = 'N';
    memcpy(msg + n, f->canon, sizeof f->canon); n += sizeof f->canon;
    msg[n++] = f->dir;
    put_be32(msg + n, f->isn); n += 4;
    put_be64(msg + n, seq); n += 8;
    put_be32(msg + n, len); n += 4;

    uint8_t full[32];
    if (hmac_sha256(s->nonce_master, sizeof s->nonce_master, msg, n, full) != 0)
        return -1;
    memcpy(nonce, full, GCM_NONCE_LEN);
    return 0;
}

/* aad = 'A' | flow | isn | seq64 : binds the ciphertext to its connection and
 * stream position, so a valid payload cannot be replayed into another
 * flow/offset. */
static size_t build_aad(const struct flowid *f, uint64_t seq, uint8_t *aad)
{
    size_t n = 0;
    aad[n++] = 'A';
    memcpy(aad + n, f->canon, sizeof f->canon); n += sizeof f->canon;
    aad[n++] = f->dir;
    put_be32(aad + n, f->isn); n += 4;
    put_be64(aad + n, seq); n += 8;
    return n;
}

int session_seal(struct session *s, const struct flowid *f, uint64_t seq,
                 const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[GCM_TAG_LEN])
{
    uint8_t nonce[GCM_NONCE_LEN], aad[AAD_LEN];
    if (derive_nonce(s, f, seq, (uint32_t)len, nonce) != 0)
        return -1;
    size_t aad_len = build_aad(f, seq, aad);

    int n = 0, total = 0;
    if (EVP_EncryptInit_ex(s->enc, NULL, NULL, NULL, nonce) != 1) return -1;
    if (EVP_EncryptUpdate(s->enc, NULL, &n, aad, (int)aad_len) != 1) return -1;
    if (EVP_EncryptUpdate(s->enc, ct, &n, pt, (int)len) != 1) return -1;
    total = n;
    if (EVP_EncryptFinal_ex(s->enc, ct + total, &n) != 1) return -1;
    total += n;
    if ((size_t)total != len) return -1;
    if (EVP_CIPHER_CTX_ctrl(s->enc, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) return -1;
    return 0;
}

int session_open(struct session *s, const struct flowid *f, uint64_t seq,
                 const uint8_t *ct, size_t len, const uint8_t tag[GCM_TAG_LEN],
                 uint8_t *pt)
{
    uint8_t nonce[GCM_NONCE_LEN], aad[AAD_LEN], tag_copy[GCM_TAG_LEN];
    if (derive_nonce(s, f, seq, (uint32_t)len, nonce) != 0)
        return -1;
    size_t aad_len = build_aad(f, seq, aad);
    memcpy(tag_copy, tag, GCM_TAG_LEN);

    int n = 0, total = 0;
    if (EVP_DecryptInit_ex(s->dec, NULL, NULL, NULL, nonce) != 1) return -1;
    if (EVP_DecryptUpdate(s->dec, NULL, &n, aad, (int)aad_len) != 1) return -1;
    if (EVP_DecryptUpdate(s->dec, pt, &n, ct, (int)len) != 1) return -1;
    total = n;
    if (EVP_CIPHER_CTX_ctrl(s->dec, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag_copy) != 1) return -1;
    if (EVP_DecryptFinal_ex(s->dec, pt + total, &n) != 1) return -1;   /* tag check */
    total += n;
    return (size_t)total == len ? 0 : -1;
}

/* ---- PSK file ---------------------------------------------------------- */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int load_psk(const char *path, uint8_t psk[PSK_LEN])
{
    FILE *f = fopen(path, "re");
    if (!f) {
        fprintf(stderr, "crypto: cannot open PSK file '%s': %s\n", path, strerror(errno));
        return -1;
    }
    char text[256];
    size_t n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = '\0';
    while (n > 0 && isspace((unsigned char)text[n - 1]))
        text[--n] = '\0';

    if (n != PSK_LEN * 2) {
        fprintf(stderr, "crypto: PSK must be %d hex chars "
                        "(openssl rand -hex 32 > psk.hex)\n", PSK_LEN * 2);
        return -1;
    }
    for (size_t i = 0; i < PSK_LEN; i++) {
        int hi = hexval(text[2 * i]), lo = hexval(text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "crypto: PSK contains a non-hex character\n");
            OPENSSL_cleanse(text, sizeof text);
            return -1;
        }
        psk[i] = (uint8_t)((hi << 4) | lo);
    }
    OPENSSL_cleanse(text, sizeof text);
    return 0;
}
