// Minimal MD5 (RFC 1321) - a direct, unoptimised implementation.
//
// Only used to compute identifier hashes that the security ecosystem defines in
// terms of MD5 (imphash, Rich-header hash). Not for integrity or secrecy.
//
// The algorithm: pad the message to a multiple of 64 bytes (append 0x80, then
// zeros, then the original bit-length as a 64-bit little-endian value), then run
// the 64-step compression over each 64-byte block updating four 32-bit words.

#include "md5.h"

#include <string.h>
#include <stdint.h>

// Per-round left-rotate amounts and the precomputed sine-derived constants K,
// exactly as tabulated in RFC 1321.
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
static const uint32_t R[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rotl(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

// Compresses one 64-byte block into the running state a0..d0.
static void md5_block(const unsigned char *p, uint32_t st[4])
{
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        // Message words are little-endian.
        M[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
               ((uint32_t)p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t ff, g;
        if (i < 16)      { ff = (b & c) | (~b & d);          g = i; }
        else if (i < 32) { ff = (d & b) | (~d & c);          g = (5 * i + 1) % 16; }
        else if (i < 48) { ff = b ^ c ^ d;                   g = (3 * i + 5) % 16; }
        else             { ff = c ^ (b | ~d);                g = (7 * i) % 16; }
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl(a + ff + K[i] + M[g], R[i]);
        a = tmp;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void md5_hex(const unsigned char *data, size_t len, char out[33])
{
    uint32_t st[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

    // Process every whole 64-byte block directly from the input.
    size_t full = len & ~(size_t)63;
    for (size_t off = 0; off < full; off += 64) {
        md5_block(data + off, st);
    }

    // Build the final padded block(s) from the trailing bytes. The padding is
    // 0x80, then zeros, then the 64-bit bit-length; it needs one extra block
    // when the remainder leaves no room for the 9 mandatory trailing bytes.
    unsigned char tail[128];
    size_t rem = len - full;
    memcpy(tail, data + full, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - (rem + 1) - 8);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        tail[padded - 8 + i] = (unsigned char)(bits >> (8 * i));
    }
    md5_block(tail, st);
    if (padded == 128) {
        md5_block(tail + 64, st);
    }

    // Emit the digest, each state word little-endian, as lowercase hex.
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned char byte = (unsigned char)(st[i] >> (8 * j));
            out[(i * 4 + j) * 2]     = hexd[byte >> 4];
            out[(i * 4 + j) * 2 + 1] = hexd[byte & 0xF];
        }
    }
    out[32] = '\0';
}
