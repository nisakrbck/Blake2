#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define U8TO32_BIG(p) \
  (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | ((uint32_t)(p)[3]))

#define U32TO8_BIG(p, v) do { \
    (p)[0] = (uint8_t)((v) >> 24); \
    (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >> 8);  \
    (p)[3] = (uint8_t)(v);         \
} while (0)

#define ROT(x,n) (((x)<<(32-n))|((x)>>(n)))

typedef struct {
    uint32_t h[8];
    uint32_t s[4];
    uint32_t t[2];
    uint8_t buf[64];
    int buflen;
    int nullt;
} state256;

const uint32_t u256[8] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89
};

// Sigma sabitleri
static const uint8_t sigma[14][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8}
};

#define G(a, b, c, d, m1, m2)               \
    v[a] = v[a] + v[b] + (m1);              \
    v[d] = ROT(v[d] ^ v[a], 16);            \
    v[c] = v[c] + v[d];                     \
    v[b] = ROT(v[b] ^ v[c], 12);            \
    v[a] = v[a] + v[b] + (m2);              \
    v[d] = ROT(v[d] ^ v[a], 8);             \
    v[c] = v[c] + v[d];                     \
    v[b] = ROT(v[b] ^ v[c], 7);

void blake256_compress(state256 *S, const uint8_t *block) {
    uint32_t v[16], m[16];
    int i, round;

    for (i = 0; i < 16; ++i)
        m[i] = U8TO32_BIG(block + i * 4);

    for (i = 0; i < 8; ++i) v[i] = S->h[i];
    for (i = 0; i < 8; ++i) v[i + 8] = u256[i];

    if (!S->nullt) {
        v[12] ^= S->t[0];
        v[13] ^= S->t[0];
        v[14] ^= S->t[1];
        v[15] ^= S->t[1];
    }

    for (round = 0; round < 14; ++round) {
        const uint8_t *s = sigma[round];
        G( 0, 4, 8,12, m[s[0]], m[s[1]]);
        G( 1, 5, 9,13, m[s[2]], m[s[3]]);
        G( 2, 6,10,14, m[s[4]], m[s[5]]);
        G( 3, 7,11,15, m[s[6]], m[s[7]]);
        G( 0, 5,10,15, m[s[8]], m[s[9]]);
        G( 1, 6,11,12, m[s[10]], m[s[11]]);
        G( 2, 7, 8,13, m[s[12]], m[s[13]]);
        G( 3, 4, 9,14, m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

void blake256_init(state256 *S) {
    S->h[0] = 0x6a09e667;
    S->h[1] = 0xbb67ae85;
    S->h[2] = 0x3c6ef372;
    S->h[3] = 0xa54ff53a;
    S->h[4] = 0x510e527f;
    S->h[5] = 0x9b05688c;
    S->h[6] = 0x1f83d9ab;
    S->h[7] = 0x5be0cd19;
    S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
    memset(S->s, 0, sizeof(S->s));
}

void blake256_update(state256 *S, const uint8_t *in, uint64_t inlen) {
    while (inlen >= 64) {
        S->t[0] += 512;
        if (S->t[0] < 512)
            S->t[1]++;
        blake256_compress(S, in);
        in += 64;
        inlen -= 64;
    }
    memcpy(S->buf, in, inlen);
    S->buflen = inlen;
}

void blake256_final(state256 *S, uint8_t *out) {
    uint64_t totalBits = ((uint64_t)S->t[1] << 32) | S->t[0];
    totalBits += S->buflen * 8;

    // Pad ekleniyor
    S->buf[S->buflen++] = 0x80;

    if (S->buflen > 56) {
        while (S->buflen < 64)
            S->buf[S->buflen++] = 0x00;
        blake256_compress(S, S->buf);
        S->buflen = 0;
    }

    while (S->buflen < 56)
        S->buf[S->buflen++] = 0x00;

    for (int i = 0; i < 8; ++i)
        S->buf[56 + i] = (totalBits >> ((7 - i) * 8)) & 0xFF;

    blake256_compress(S, S->buf);

    for (int i = 0; i < 8; i++)
        U32TO8_BIG(out + i * 4, S->h[i]);
}


void blake256_hash(uint8_t *out, const uint8_t *in, uint64_t inlen) {
    state256 S;
    blake256_init(&S);
    blake256_update(&S, in, inlen);
    blake256_final(&S, out);
}

int main() {
    const char *filename = "test.txt";

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: Unable to open file %s\n", filename);
        return 1;
    }

    uint8_t buffer[64], hash[32];
    state256 S;
    blake256_init(&S);

    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, 64, fp)) > 0) {
        blake256_update(&S, buffer, bytesRead);
    }
    fclose(fp);

    blake256_final(&S, hash);

    printf("BLAKE-256 Hash of %s:\n\n", filename);

    int i;  // <-- i burada tanýmlandý
    for (i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}

