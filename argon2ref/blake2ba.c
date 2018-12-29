/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0 
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "argon2ref/blake2.h"
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blake2b-round.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif
 #define HAVE_AVX

#if defined(HAVE_SSE2)
#include <emmintrin.h>
 // MSVC only defines  _mm_set_epi64x for x86_64...
#if defined(_MSC_VER) && !defined(_M_X64)
static inline __m128i _mm_set_epi64x(const uint64_t u1, const uint64_t u0)
{
	return _mm_set_epi32(u1 >> 32, u1, u0 >> 32, u0);
}
#endif
#endif

#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE4_1)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP) && !defined(_MSC_VER)
#include <x86intrin.h>
#endif



static const uint64_t ablake2b_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

static const unsigned int ablake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static BLAKE2_INLINE void ablake2b_set_lastnode(ablake2b_state *S) {
    S->f[1] = (uint64_t)-1;
}

static BLAKE2_INLINE void ablake2b_set_lastblock(ablake2b_state *S) {
    if (S->last_node) {
        ablake2b_set_lastnode(S);
    }
    S->f[0] = (uint64_t)-1;
}

static BLAKE2_INLINE void ablake2b_increment_counter(ablake2b_state *S,
                                                    uint64_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static BLAKE2_INLINE void ablake2b_invalidate_state(ablake2b_state *S) {
    clear_internal_memory(S, sizeof(*S));      /* wipe */
    ablake2b_set_lastblock(S); /* invalidate for further use */
}

static BLAKE2_INLINE void ablake2b_init0(ablake2b_state *S) {
    memset(S, 0, sizeof(*S));
    memcpy(S->h, ablake2b_IV, sizeof(S->h));
}

 int ablake2b_init_param(ablake2b_state *S, const ablake2b_param *P) {
    const unsigned char *p = (const unsigned char *)P;
    unsigned int i;

    if (NULL == P || NULL == S) {
        return -1;
    }

    ablake2b_init0(S);
    /* IV XOR Parameter Block */
    for (i = 0; i < 8; ++i) {
        S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
    }
    S->outlen = P->digest_length;
    return 0;
}

/* Sequential blake2b initialization */
 int ablake2b_init(ablake2b_state *S, size_t outlen) {
    ablake2b_param P;

    if (S == NULL) {
        return -1;
    }

    if ((outlen == 0) || (outlen > ablake2b_OUTBYTES)) {
        ablake2b_invalidate_state(S);
        return -1;
    }

    /* Setup Parameter Block for unkeyed BLAKE2 */
    P.digest_length = (uint8_t)outlen;
    P.key_length = 0;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    return ablake2b_init_param(S, &P);
}

 int ablake2b_init_key(ablake2b_state *S, size_t outlen, const void *key,
                     size_t keylen) {
    ablake2b_param P;

    if (S == NULL) {
        return -1;
    }

    if ((outlen == 0) || (outlen > ablake2b_OUTBYTES)) {
        ablake2b_invalidate_state(S);
        return -1;
    }

    if ((key == 0) || (keylen == 0) || (keylen > ablake2b_KEYBYTES)) {
        ablake2b_invalidate_state(S);
        return -1;
    }

    /* Setup Parameter Block for keyed BLAKE2 */
    P.digest_length = (uint8_t)outlen;
    P.key_length = (uint8_t)keylen;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    if (ablake2b_init_param(S, &P) < 0) {
        ablake2b_invalidate_state(S);
        return -1;
    }

    {
        uint8_t block[ablake2b_BLOCKBYTES];
        memset(block, 0, ablake2b_BLOCKBYTES);
        memcpy(block, key, keylen);
        ablake2b_update(S, block, ablake2b_BLOCKBYTES);
        /* Burn the key from stack */
        clear_internal_memory(block, ablake2b_BLOCKBYTES);
    }
    return 0;
}



 static inline int ablake2b_compress(ablake2b_state *S, const uint8_t block[ablake2b_BLOCKBYTES])
 {
	 __m128i row1l, row1h;
	 __m128i row2l, row2h;
	 __m128i row3l, row3h;
	 __m128i row4l, row4h;
	 __m128i b0, b1;
	 __m128i t0, t1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
	 const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	 const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
#endif
#if defined(HAVE_SSE4_1)
	 const __m128i m0 = LOADU(block + 00);
	 const __m128i m1 = LOADU(block + 16);
	 const __m128i m2 = LOADU(block + 32);
	 const __m128i m3 = LOADU(block + 48);
	 const __m128i m4 = LOADU(block + 64);
	 const __m128i m5 = LOADU(block + 80);
	 const __m128i m6 = LOADU(block + 96);
	 const __m128i m7 = LOADU(block + 112);
#else
	 const uint64_t  m0 = ((uint64_t *)block)[0];
	 const uint64_t  m1 = ((uint64_t *)block)[1];
	 const uint64_t  m2 = ((uint64_t *)block)[2];
	 const uint64_t  m3 = ((uint64_t *)block)[3];
	 const uint64_t  m4 = ((uint64_t *)block)[4];
	 const uint64_t  m5 = ((uint64_t *)block)[5];
	 const uint64_t  m6 = ((uint64_t *)block)[6];
	 const uint64_t  m7 = ((uint64_t *)block)[7];
	 const uint64_t  m8 = ((uint64_t *)block)[8];
	 const uint64_t  m9 = ((uint64_t *)block)[9];
	 const uint64_t m10 = ((uint64_t *)block)[10];
	 const uint64_t m11 = ((uint64_t *)block)[11];
	 const uint64_t m12 = ((uint64_t *)block)[12];
	 const uint64_t m13 = ((uint64_t *)block)[13];
	 const uint64_t m14 = ((uint64_t *)block)[14];
	 const uint64_t m15 = ((uint64_t *)block)[15];
#endif

	 row1l = LOADU(&S->h[0]);
	 row1h = LOADU(&S->h[2]);
	 row2l = LOADU(&S->h[4]);
	 row2h = LOADU(&S->h[6]);
	 row3l = LOADU(&ablake2b_IV[0]);
	 row3h = LOADU(&ablake2b_IV[2]);
	 row4l = _mm_xor_si128(LOADU(&ablake2b_IV[4]), LOADU(&S->t[0]));
	 row4h = _mm_xor_si128(LOADU(&ablake2b_IV[6]), LOADU(&S->f[0]));
	 ROUND(0);
	 ROUND(1);
	 ROUND(2);
	 ROUND(3);
	 ROUND(4);
	 ROUND(5);
	 ROUND(6);
	 ROUND(7);
	 ROUND(8);
	 ROUND(9);
	 ROUND(10);
	 ROUND(11);
	 row1l = _mm_xor_si128(row3l, row1l);
	 row1h = _mm_xor_si128(row3h, row1h);
	 STOREU(&S->h[0], _mm_xor_si128(LOADU(&S->h[0]), row1l));
	 STOREU(&S->h[2], _mm_xor_si128(LOADU(&S->h[2]), row1h));
	 row2l = _mm_xor_si128(row4l, row2l);
	 row2h = _mm_xor_si128(row4h, row2h);
	 STOREU(&S->h[4], _mm_xor_si128(LOADU(&S->h[4]), row2l));
	 STOREU(&S->h[6], _mm_xor_si128(LOADU(&S->h[6]), row2h));

	 return 0;
 }


 static inline int ablake2b4rounds_compress(ablake2b_state *S, const uint8_t block[ablake2b_BLOCKBYTES])
 {
	 __m128i row1l, row1h;
	 __m128i row2l, row2h;
	 __m128i row3l, row3h;
	 __m128i row4l, row4h;
	 __m128i b0, b1;
	 __m128i t0, t1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
	 const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	 const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
#endif
#if defined(HAVE_SSE4_1)
	 const __m128i m0 = LOADU(block + 00);
	 const __m128i m1 = LOADU(block + 16);
	 const __m128i m2 = LOADU(block + 32);
	 const __m128i m3 = LOADU(block + 48);
	 const __m128i m4 = LOADU(block + 64);
	 const __m128i m5 = LOADU(block + 80);
	 const __m128i m6 = LOADU(block + 96);
	 const __m128i m7 = LOADU(block + 112);
#else
	 const uint64_t  m0 = ((uint64_t *)block)[0];
	 const uint64_t  m1 = ((uint64_t *)block)[1];
	 const uint64_t  m2 = ((uint64_t *)block)[2];
	 const uint64_t  m3 = ((uint64_t *)block)[3];
	 const uint64_t  m4 = ((uint64_t *)block)[4];
	 const uint64_t  m5 = ((uint64_t *)block)[5];
	 const uint64_t  m6 = ((uint64_t *)block)[6];
	 const uint64_t  m7 = ((uint64_t *)block)[7];
	 const uint64_t  m8 = ((uint64_t *)block)[8];
	 const uint64_t  m9 = ((uint64_t *)block)[9];
	 const uint64_t m10 = ((uint64_t *)block)[10];
	 const uint64_t m11 = ((uint64_t *)block)[11];
	 const uint64_t m12 = ((uint64_t *)block)[12];
	 const uint64_t m13 = ((uint64_t *)block)[13];
	 const uint64_t m14 = ((uint64_t *)block)[14];
	 const uint64_t m15 = ((uint64_t *)block)[15];
#endif
	 row1l = LOADU(&S->h[0]);
	 row1h = LOADU(&S->h[2]);
	 row2l = LOADU(&S->h[4]);
	 row2h = LOADU(&S->h[6]);
	 row3l = LOADU(&ablake2b_IV[0]);
	 row3h = LOADU(&ablake2b_IV[2]);
	 row4l = _mm_xor_si128(LOADU(&ablake2b_IV[4]), LOADU(&S->t[0]));
	 row4h = _mm_xor_si128(LOADU(&ablake2b_IV[6]), LOADU(&S->f[0]));
	 ROUND(0);
	 ROUND(1);
	 ROUND(2);
	 ROUND(3);
	 row1l = _mm_xor_si128(row3l, row1l);
	 row1h = _mm_xor_si128(row3h, row1h);
	 STOREU(&S->h[0], _mm_xor_si128(LOADU(&S->h[0]), row1l));
	 STOREU(&S->h[2], _mm_xor_si128(LOADU(&S->h[2]), row1h));
	 row2l = _mm_xor_si128(row4l, row2l);
	 row2h = _mm_xor_si128(row4h, row2h);
	 STOREU(&S->h[4], _mm_xor_si128(LOADU(&S->h[4]), row2l));
	 STOREU(&S->h[6], _mm_xor_si128(LOADU(&S->h[6]), row2h));
	 return 0;
 }



 void ablake2b_compress_old(ablake2b_state *S, const uint8_t *block) {

    uint64_t m[16];
    uint64_t v[16];
    unsigned int i, r;


    for (i = 0; i < 16; ++i) {
        m[i] = load64(block + i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
        v[i] = S->h[i];
    }
    v[8] = ablake2b_IV[0];
    v[9] = ablake2b_IV[1];
    v[10] = ablake2b_IV[2];
    v[11] = ablake2b_IV[3];
    v[12] = ablake2b_IV[4] ^ S->t[0];
    v[13] = ablake2b_IV[5] ^ S->t[1];
    v[14] = ablake2b_IV[6] ^ S->f[0];
    v[15] = ablake2b_IV[7] ^ S->f[1];

#define G(r, i, a, b, c, d)                                                    \
    do {                                                                       \
        a = a + b + m[ablake2b_sigma[r][2 * i + 0]];                            \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + m[ablake2b_sigma[r][2 * i + 1]];                            \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);                                      \
    } while ((void)0, 0)

    for (r = 0; r < 12; ++r) {
        ROUND(r);
    }

    for (i = 0; i < 8; ++i) {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }

#undef G
#undef ROUND
}

 void ablake2b_compress_test(ablake2b_state *S, const uint8_t *block) {

	 uint64_t m[16];
	 uint64_t v[16];
	 unsigned int i, r;
printf("coming here S %08x %08x %08x %08x\n", S->t[0], S->t[1], S->f[0], S->f[1]);


printf("m[i] ");
	 for (i = 0; i < 16; ++i) {
		 m[i] = load64(block + i * sizeof(m[i]));
printf(" %08x %08x ", ((uint32_t*)m)[2*i], ((uint32_t*)m)[2 * i + 1]);
	 }
printf(" \n ");

printf("v[i] ");
	 for (i = 0; i < 8; ++i) {
		 v[i] = S->h[i];
printf(" %08x %08x ", ((uint32_t*)v)[2 * i], ((uint32_t*)v)[2 * i + 1]);
	 }
printf(" \n ");

	 v[8] = ablake2b_IV[0];
	 v[9] = ablake2b_IV[1];
	 v[10] = ablake2b_IV[2];
	 v[11] = ablake2b_IV[3];
	 v[12] = ablake2b_IV[4] ^ S->t[0];
	 v[13] = ablake2b_IV[5] ^ S->t[1];
	 v[14] = ablake2b_IV[6] ^ S->f[0];
	 v[15] = ablake2b_IV[7] ^ S->f[1];

#define G(r, i, a, b, c, d)                                                    \
    do {                                                                       \
        a = a + b + m[ablake2b_sigma[r][2 * i + 0]];                            \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + m[ablake2b_sigma[r][2 * i + 1]];                            \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);                                      \
    } while ((void)0, 0)

	 for (r = 0; r < 12; ++r) {
		 ROUND(r);
	 }
printf("result compress:");
	 for (i = 0; i < 8; ++i) {
		 S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
		 printf(" %08x %08x ", ((uint32_t*)S->h)[2 * i], ((uint32_t*)S->h)[2 * i + 1]);
	 }
printf(" \n");
#undef G
#undef ROUND
 }


 void ablake2b4rounds_compress_old(ablake2b_state *S, const uint8_t *block) {

	 uint64_t m[16];
	 uint64_t v[16];
	 unsigned int i, r;


	 for (i = 0; i < 16; ++i) {
		 m[i] = load64(block + i * sizeof(m[i]));
	 }

	 for (i = 0; i < 8; ++i) {
		 v[i] = S->h[i];
	 }
	 v[8] = ablake2b_IV[0];
	 v[9] = ablake2b_IV[1];
	 v[10] = ablake2b_IV[2];
	 v[11] = ablake2b_IV[3];
	 v[12] = ablake2b_IV[4] ^ S->t[0];
	 v[13] = ablake2b_IV[5] ^ S->t[1];
	 v[14] = ablake2b_IV[6] ^ S->f[0];
	 v[15] = ablake2b_IV[7] ^ S->f[1];

#define G(r, i, a, b, c, d)                                                    \
    do {                                                                       \
        a = a + b + m[ablake2b_sigma[r][2 * i + 0]];                            \
        d = rotr64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 24);                                                 \
        a = a + b + m[ablake2b_sigma[r][2 * i + 1]];                            \
        d = rotr64(d ^ a, 16);                                                 \
        c = c + d;                                                             \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);                                      \
    } while ((void)0, 0)

	 for (r = 0; r < 4; ++r) {
		 ROUND(r);
	 }

	 for (i = 0; i < 8; ++i) {
		 S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
	 }

#undef G
#undef ROUND
 }



 int ablake2b_update(ablake2b_state *S, const void *in, size_t inlen) {
    const uint8_t *pin = (const uint8_t *)in;

    if (inlen == 0) {
        return 0;
    }

    /* Sanity check */
    if (S == NULL || in == NULL) {
        return -1;
    }

    /* Is this a reused state? */
    if (S->f[0] != 0) {
        return -1;
    }

    if (S->buflen + inlen > ablake2b_BLOCKBYTES) {
        /* Complete current block */
        size_t left = S->buflen;
        size_t fill = ablake2b_BLOCKBYTES - left;
        memcpy(&S->buf[left], pin, fill);
        ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
        ablake2b_compress(S, S->buf);
        S->buflen = 0;
        inlen -= fill;
        pin += fill;
        /* Avoid buffer copies when possible */
        while (inlen > ablake2b_BLOCKBYTES) {
            ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
            ablake2b_compress(S, pin);
            inlen -= ablake2b_BLOCKBYTES;
            pin += ablake2b_BLOCKBYTES;
        }
    }
    memcpy(&S->buf[S->buflen], pin, inlen);
    S->buflen += (unsigned int)inlen;
    return 0;
}


 int ablake2b_update_test(ablake2b_state *S, const void *in, size_t inlen) {
	 const uint8_t *pin = (const uint8_t *)in;

	 if (inlen == 0) {
		 return 0;
	 }

	 /* Sanity check */
	 if (S == NULL || in == NULL) {
		 return -1;
	 }

	 /* Is this a reused state? */
	 if (S->f[0] != 0) {
		 return -1;
	 }

	 if (S->buflen + inlen > ablake2b_BLOCKBYTES) {
		 /* Complete current block */
		 size_t left = S->buflen;
		 size_t fill = ablake2b_BLOCKBYTES - left;
		 memcpy(&S->buf[left], pin, fill);
		 ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
		 ablake2b_compress_test(S, S->buf);
		 S->buflen = 0;
		 inlen -= fill;
		 pin += fill;
		 /* Avoid buffer copies when possible */
		 while (inlen > ablake2b_BLOCKBYTES) {
			 ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
			 ablake2b_compress_test(S, pin);
			 inlen -= ablake2b_BLOCKBYTES;
			 pin += ablake2b_BLOCKBYTES;
		 }
	 }
	 memcpy(&S->buf[S->buflen], pin, inlen);
	 S->buflen += (unsigned int)inlen;
	 return 0;
 }


 int ablake2b4rounds_update(ablake2b_state *S, const void *in, size_t inlen) {
	 const uint8_t *pin = (const uint8_t *)in;

	 if (inlen == 0) {
		 return 0;
	 }

	 /* Sanity check */
	 if (S == NULL || in == NULL) {
		 return -1;
	 }

	 /* Is this a reused state? */
	 if (S->f[0] != 0) {
		 return -1;
	 }

	 if (S->buflen + inlen > ablake2b_BLOCKBYTES) {
		 /* Complete current block */
		 size_t left = S->buflen;
		 size_t fill = ablake2b_BLOCKBYTES - left;
		 memcpy(&S->buf[left], pin, fill);
		 ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
		 ablake2b4rounds_compress(S, S->buf);
		 S->buflen = 0;
		 inlen -= fill;
		 pin += fill;
		 /* Avoid buffer copies when possible */
		 while (inlen > ablake2b_BLOCKBYTES) {
			 ablake2b_increment_counter(S, ablake2b_BLOCKBYTES);
			 ablake2b4rounds_compress(S, pin);
			 inlen -= ablake2b_BLOCKBYTES;
			 pin += ablake2b_BLOCKBYTES;
		 }
	 }
	 memcpy(&S->buf[S->buflen], pin, inlen);
	 S->buflen += (unsigned int)inlen;
	 return 0;
 }



 int ablake2b_final(ablake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[ablake2b_OUTBYTES] = {0};
    unsigned int i;

    /* Sanity checks */
    if (S == NULL || out == NULL || outlen < S->outlen) {
        return -1;
    }

    /* Is this a reused state? */
    if (S->f[0] != 0) {
        return -1;
    }

    ablake2b_increment_counter(S, S->buflen);
    ablake2b_set_lastblock(S);
    memset(&S->buf[S->buflen], 0, ablake2b_BLOCKBYTES - S->buflen); /* Padding */
    ablake2b_compress(S, S->buf);

    for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
        store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
    }

    memcpy(out, buffer, S->outlen);
    clear_internal_memory(buffer, sizeof(buffer));
    clear_internal_memory(S->buf, sizeof(S->buf));
    clear_internal_memory(S->h, sizeof(S->h));
    return 0;
}

 int ablake2b_final_test(ablake2b_state *S, void *out, size_t outlen) {
	 uint8_t buffer[ablake2b_OUTBYTES] = { 0 };
	 unsigned int i;

	 /* Sanity checks */
	 if (S == NULL || out == NULL || outlen < S->outlen) {
		 return -1;
	 }

	 /* Is this a reused state? */
	 if (S->f[0] != 0) {
		 return -1;
	 }

	 ablake2b_increment_counter(S, S->buflen);
	 ablake2b_set_lastblock(S);
	 memset(&S->buf[S->buflen], 0, ablake2b_BLOCKBYTES - S->buflen); /* Padding */
	 ablake2b_compress_test(S, S->buf);

	 for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
		 store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
	 }

	 memcpy(out, buffer, S->outlen);
	 clear_internal_memory(buffer, sizeof(buffer));
	 clear_internal_memory(S->buf, sizeof(S->buf));
	 clear_internal_memory(S->h, sizeof(S->h));
	 return 0;
 }




 int ablake2b4rounds_final(ablake2b_state *S, void *out, size_t outlen) {
	 uint8_t buffer[ablake2b_OUTBYTES] = { 0 };
	 unsigned int i;

	 /* Sanity checks */
	 if (S == NULL || out == NULL || outlen < S->outlen) {
		 return -1;
	 }

	 /* Is this a reused state? */
	 if (S->f[0] != 0) {
		 return -1;
	 }

	 ablake2b_increment_counter(S, S->buflen);
	 ablake2b_set_lastblock(S);
	 memset(&S->buf[S->buflen], 0, ablake2b_BLOCKBYTES - S->buflen); /* Padding */
	 ablake2b4rounds_compress(S, S->buf);

	 for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
		 store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
	 }

	 memcpy(out, buffer, S->outlen);
	 clear_internal_memory(buffer, sizeof(buffer));
	 clear_internal_memory(S->buf, sizeof(S->buf));
	 clear_internal_memory(S->h, sizeof(S->h));
	 return 0;
 }
/*
 #define TRY(statement)                                                         \
    do {                                                                       \
        ret = statement;                                                       \
        if (ret < 0) {                                                         \
            goto fail;                                                         \
        }                                                                      \
    } while ((void)0, 0)                                                       \
*/
 
 int ablake2b_long(void * pout, size_t outlen, const void * in, size_t inlen)
 {

	 uint8_t *out = (uint8_t *)pout;
	 ablake2b_state blake_state;
	 uint8_t outlen_bytes[sizeof(uint32_t)] = { 0 };
	 int ret = -1;

	 if (outlen > UINT32_MAX) 
		 goto fail;
	 
	 /* Ensure little-endian byte order! */
	 store32(outlen_bytes, (uint32_t)outlen);
	 if (outlen <= ablake2b_OUTBYTES) {


		 if (ablake2b_init(&blake_state, outlen)) goto fail;
		 if (ablake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes))) goto fail;
		 if (ablake2b_update(&blake_state, in, inlen)) goto fail;
		 if (ablake2b_final(&blake_state, out, outlen)) goto fail;
	 }
	 else {

		 uint32_t toproduce;
		 uint8_t out_buffer[ablake2b_OUTBYTES];
		 uint8_t in_buffer[ablake2b_OUTBYTES];
		 if (ablake2b_init(&blake_state, ablake2b_OUTBYTES))  goto fail;
		 if (ablake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)))  goto fail;
		 if (ablake2b_update(&blake_state, in, inlen))  goto fail;
		 if (ablake2b_final(&blake_state, out_buffer, ablake2b_OUTBYTES))  goto fail;
		 memcpy(out, out_buffer, ablake2b_OUTBYTES / 2);
		 out += ablake2b_OUTBYTES / 2;
		 toproduce = (uint32_t)outlen - ablake2b_OUTBYTES / 2;
uint32_t count = 0;

		 while (toproduce > ablake2b_OUTBYTES) {

			 memcpy(in_buffer, out_buffer, ablake2b_OUTBYTES);
			 if (blake2b(out_buffer, ablake2b_OUTBYTES, in_buffer,
				 ablake2b_OUTBYTES, NULL, 0))  goto fail;
			 memcpy(out, out_buffer, ablake2b_OUTBYTES / 2);
			 out += ablake2b_OUTBYTES / 2;
			 toproduce -= ablake2b_OUTBYTES / 2;
		 count++;

		 }

		 memcpy(in_buffer, out_buffer, ablake2b_OUTBYTES);
		 if (blake2b(out_buffer, toproduce, in_buffer, ablake2b_OUTBYTES, NULL,
			 0))  goto fail;

		 memcpy(out, out_buffer, toproduce);

	 }
 fail:
	 clear_internal_memory(&blake_state, sizeof(blake_state));


	 return ret;	 
 }




int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen) 
{
    ablake2b_state S;
    int ret = -1;

    /* Verify parameters */
    if (NULL == in && inlen > 0) 
        goto fail;

    if (NULL == out || outlen == 0 || outlen > ablake2b_OUTBYTES) 
        goto fail;
    
    if ((NULL == key && keylen > 0) || keylen > ablake2b_KEYBYTES) 
        goto fail;   

    if (keylen > 0) {
        if (ablake2b_init_key(&S, outlen, key, keylen) < 0) {
            goto fail;
        }
    } else {
        if (ablake2b_init(&S, outlen) < 0) {
            goto fail;
        }
    }

    if (ablake2b_update(&S, in, inlen) < 0) 
        goto fail;
    
    ret = ablake2b_final(&S, out, outlen);

fail:
    clear_internal_memory(&S, sizeof(S));
    return ret;
}


//#undef TRY