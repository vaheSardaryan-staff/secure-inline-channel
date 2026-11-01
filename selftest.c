/* selftest.c - unit checks for the crypto module. Build: make test */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "crypto.h"

static int fail;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fail = 1; } \
                           else printf("ok  : %s\n", msg); } while (0)

int main(void)
{
    crypto_global_init();
    uint8_t psk[PSK_LEN];
    memset(psk, 0x5a, sizeof psk);

    /* Two parties do ephemeral DH and must agree on identical sessions. */
    struct handshake a, b;
    CHECK(handshake_init(&a) == 0 && handshake_init(&b) == 0, "DH keygen");
    struct session sa, sb;
    CHECK(session_derive(&a, b.pub, psk, &sa) == 0, "derive A");
    CHECK(session_derive(&b, a.pub, psk, &sb) == 0, "derive B");
    CHECK(memcmp(sa.confirm, sb.confirm, CONFIRM_LEN) == 0, "confirmation values match");
    CHECK(memcmp(sa.nonce_master, sb.nonce_master, 32) == 0, "nonce master matches");

    /* A different PSK must yield a different confirmation (auth works). */
    struct session sc;
    uint8_t psk2[PSK_LEN]; memset(psk2, 0x11, sizeof psk2);
    CHECK(session_derive(&a, b.pub, psk2, &sc) == 0, "derive with wrong PSK");
    CHECK(memcmp(sa.confirm, sc.confirm, CONFIRM_LEN) != 0, "wrong PSK -> different confirm");

    /* Round trip: A seals, B opens, plaintext restored. */
    struct flowid f; memset(&f, 0, sizeof f);
    for (int i = 0; i < 12; i++) f.canon[i] = (uint8_t)i;
    f.dir = 0;
    uint8_t pt[1400], ct[1400], rt[1400], tag[GCM_TAG_LEN];
    for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i * 7 + 1);

    CHECK(session_seal(&sa, &f, 1000, pt, sizeof pt, ct, tag) == 0, "seal");
    CHECK(memcmp(pt, ct, sizeof pt) != 0, "ciphertext differs from plaintext");
    CHECK(session_open(&sb, &f, 1000, ct, sizeof pt, tag, rt) == 0, "open");
    CHECK(memcmp(pt, rt, sizeof pt) == 0, "plaintext restored");

    /* Tamper in each field must fail authentication. */
    uint8_t bad[1400];
    memcpy(bad, ct, sizeof ct); bad[10] ^= 1;
    CHECK(session_open(&sb, &f, 1000, bad, sizeof pt, tag, rt) != 0, "flipped ciphertext rejected");
    uint8_t badtag[GCM_TAG_LEN]; memcpy(badtag, tag, sizeof tag); badtag[0] ^= 1;
    CHECK(session_open(&sb, &f, 1000, ct, sizeof pt, badtag, rt) != 0, "flipped tag rejected");
    CHECK(session_open(&sb, &f, 1001, ct, sizeof pt, tag, rt) != 0, "wrong seq (AAD) rejected");
    struct flowid f2 = f; f2.dir = 1;
    CHECK(session_open(&sb, &f2, 1000, ct, sizeof pt, tag, rt) != 0, "wrong direction rejected");

    /* Nonce uniqueness: seal the same plaintext under many (seq,len) and verify
     * the ciphertexts are all distinct (distinct nonce => distinct keystream). */
    enum { N = 4000 };
    static uint8_t first16[N][16];
    int uniq = 1;
    for (int i = 0; i < N; i++) {
        session_seal(&sa, &f, 2000 + (uint32_t)i, pt, 64, ct, tag);
        memcpy(first16[i], ct, 16);
        for (int j = 0; j < i; j++)
            if (memcmp(first16[i], first16[j], 16) == 0) { uniq = 0; break; }
    }
    CHECK(uniq, "distinct nonce per packet (4000 seqs, no keystream reuse)");

    /* Determinism: identical (flow,seq,len,plaintext) -> identical output,
     * which is why a TCP retransmission is safe. */
    uint8_t ct2[1400], tag2[GCM_TAG_LEN];
    session_seal(&sa, &f, 9, pt, 100, ct, tag);
    session_seal(&sa, &f, 9, pt, 100, ct2, tag2);
    CHECK(memcmp(ct, ct2, 100) == 0 && memcmp(tag, tag2, 16) == 0,
          "same packet -> same ciphertext (retransmit-safe)");

    session_free(&sa); session_free(&sb); session_free(&sc);
    handshake_free(&a); handshake_free(&b);
    printf(fail ? "\nSELFTEST FAILED\n" : "\nALL SELFTESTS PASSED\n");
    return fail;
}
