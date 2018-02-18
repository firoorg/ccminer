///////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// sha256 Transform function /////////////////////////
//////// djm34 2017
#include "lyra2\cuda_lyra2_vectors.h"

static __constant__ uint8 pad4 =
{
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100
};

static __constant__ uint16 pad64 =
{
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000200
};



static __constant__  uint8 H256 = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372,
	0xA54FF53A, 0x510E527F, 0x9B05688C,
	0x1F83D9AB, 0x5BE0CD19
};

static  __constant__  uint32_t Ksha[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define xor3b(a,b,c) (a ^ b ^ c)

static __device__ __forceinline__ uint32_t bsg2_0(const uint32_t x)
{
	uint32_t r1 = ROTR32(x, 2);
	uint32_t r2 = ROTR32(x, 13);
	uint32_t r3 = ROTR32(x, 22);
	return xor3b(r1, r2, r3);
}

static __device__ __forceinline__ uint2 bsg2_0(const uint2 x)
{
	uint2 r1 = ROR2(x, 2);
	r1 ^= ROR2(x, 13);
	r1 ^= ROR2(x, 22);
	return r1;
}



static __device__ __forceinline__ uint32_t bsg2_1(const uint32_t x)
{

	uint32_t r1 = ROTR32(x, 6);
	uint32_t r2 = ROTR32(x, 11);
	uint32_t r3 = ROTR32(x, 25);
	return xor3b(r1, r2, r3);
}

static __device__ __forceinline__ uint2 bsg2_1(const uint2 x)
{
	uint2 r1 = ROR2(x, 6);
	r1 ^= ROR2(x, 11);
	r1 ^= ROR2(x, 25);
	return r1;
}


static __device__ __forceinline__ uint32_t ssg2_0(const uint32_t x)
{
	uint32_t r1 = ROTR32(x, 7);
	uint32_t r2 = ROTR32(x, 18);
	uint32_t r3 = shr_t32(x, 3);
	return xor3b(r1, r2, r3);
}



static __device__ __forceinline__ uint32_t ssg2_1(const uint32_t x)
{
	uint32_t r1 = ROTR32(x, 17);
	uint32_t r2 = ROTR32(x, 19);
	uint32_t r3 = shr_t32(x, 10);
	return xor3b(r1, r2, r3);
}

static __device__ __forceinline__ void sha2_step1(const uint32_t a, const uint32_t b, const uint32_t c, uint32_t &d, const uint32_t e,
	const uint32_t f, const uint32_t g, uint32_t &h, const uint32_t in, const uint32_t Kshared)
{
	uint32_t t1, t2;

	uint32_t vxandx = xandx(e, f, g);

	uint32_t bsg21 = bsg2_1(e);
	uint32_t bsg20 = bsg2_0(a);

	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); //andor32(a, b, c);

	t1 = h + bsg21 + vxandx + Kshared + in;
	t2 = bsg20 + andorv;
	d = d + t1;
	h = t1 + t2;
}

static __device__ __forceinline__ void sha2_step2(const uint32_t a, const uint32_t b, const uint32_t c, uint32_t &d, const uint32_t e,
	const uint32_t f, const uint32_t g, uint32_t &h, uint32_t* in, const uint32_t pc, const uint32_t Kshared)
{
	uint32_t t1, t2;

	int pcidx1 = (pc - 2) & 0xF;
	int pcidx2 = (pc - 7) & 0xF;
	int pcidx3 = (pc - 15) & 0xF;
	uint32_t inx0 = in[pc];
	uint32_t inx1 = in[pcidx1];
	uint32_t inx2 = in[pcidx2];
	uint32_t inx3 = in[pcidx3];

	uint32_t ssg21 = ssg2_1(inx1);
	uint32_t ssg20 = ssg2_0(inx3);

	uint32_t vxandx = xandx(e, f, g);

	uint32_t bsg21 = bsg2_1(e);
	uint32_t bsg20 = bsg2_0(a);

	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); //andor32(a, b, c);
 
	in[pc] = ssg21 + inx2 + ssg20 + inx0;

	t1 = h + bsg21 + vxandx + Kshared + in[pc];
	t2 = bsg20 + andorv;
	d = d + t1;
	h = t1 + t2;
}




static __device__ __forceinline__
uint8 sha256_Transform2(uint16 in[1], const uint8 &r) // also known as sha2_round_body
{
	uint8 tmp = r;
#define a  tmp.s0
#define b  tmp.s1
#define c  tmp.s2
#define d  tmp.s3
#define e  tmp.s4
#define f  tmp.s5
#define g  tmp.s6
#define h  tmp.s7

	sha2_step1(a, b, c, d, e, f, g, h, in[0].s0, Ksha[0]);
	sha2_step1(h, a, b, c, d, e, f, g, in[0].s1, Ksha[1]);
	sha2_step1(g, h, a, b, c, d, e, f, in[0].s2, Ksha[2]);
	sha2_step1(f, g, h, a, b, c, d, e, in[0].s3, Ksha[3]);
	sha2_step1(e, f, g, h, a, b, c, d, in[0].s4, Ksha[4]);
	sha2_step1(d, e, f, g, h, a, b, c, in[0].s5, Ksha[5]);
	sha2_step1(c, d, e, f, g, h, a, b, in[0].s6, Ksha[6]);
	sha2_step1(b, c, d, e, f, g, h, a, in[0].s7, Ksha[7]);
	sha2_step1(a, b, c, d, e, f, g, h, in[0].s8, Ksha[8]);
	sha2_step1(h, a, b, c, d, e, f, g, in[0].s9, Ksha[9]);
	sha2_step1(g, h, a, b, c, d, e, f, in[0].sa, Ksha[10]);
	sha2_step1(f, g, h, a, b, c, d, e, in[0].sb, Ksha[11]);
	sha2_step1(e, f, g, h, a, b, c, d, in[0].sc, Ksha[12]);
	sha2_step1(d, e, f, g, h, a, b, c, in[0].sd, Ksha[13]);
	sha2_step1(c, d, e, f, g, h, a, b, in[0].se, Ksha[14]);
	sha2_step1(b, c, d, e, f, g, h, a, in[0].sf, Ksha[15]);

#pragma unroll 3
	for (int i = 0; i<3; i++) {

		sha2_step2(a, b, c, d, e, f, g, h, (uint32_t*)in, 0, Ksha[16 + 16 * i]);
		sha2_step2(h, a, b, c, d, e, f, g, (uint32_t*)in, 1, Ksha[17 + 16 * i]);
		sha2_step2(g, h, a, b, c, d, e, f, (uint32_t*)in, 2, Ksha[18 + 16 * i]);
		sha2_step2(f, g, h, a, b, c, d, e, (uint32_t*)in, 3, Ksha[19 + 16 * i]);
		sha2_step2(e, f, g, h, a, b, c, d, (uint32_t*)in, 4, Ksha[20 + 16 * i]);
		sha2_step2(d, e, f, g, h, a, b, c, (uint32_t*)in, 5, Ksha[21 + 16 * i]);
		sha2_step2(c, d, e, f, g, h, a, b, (uint32_t*)in, 6, Ksha[22 + 16 * i]);
		sha2_step2(b, c, d, e, f, g, h, a, (uint32_t*)in, 7, Ksha[23 + 16 * i]);
		sha2_step2(a, b, c, d, e, f, g, h, (uint32_t*)in, 8, Ksha[24 + 16 * i]);
		sha2_step2(h, a, b, c, d, e, f, g, (uint32_t*)in, 9, Ksha[25 + 16 * i]);
		sha2_step2(g, h, a, b, c, d, e, f, (uint32_t*)in, 10, Ksha[26 + 16 * i]);
		sha2_step2(f, g, h, a, b, c, d, e, (uint32_t*)in, 11, Ksha[27 + 16 * i]);
		sha2_step2(e, f, g, h, a, b, c, d, (uint32_t*)in, 12, Ksha[28 + 16 * i]);
		sha2_step2(d, e, f, g, h, a, b, c, (uint32_t*)in, 13, Ksha[29 + 16 * i]);
		sha2_step2(c, d, e, f, g, h, a, b, (uint32_t*)in, 14, Ksha[30 + 16 * i]);
		sha2_step2(b, c, d, e, f, g, h, a, (uint32_t*)in, 15, Ksha[31 + 16 * i]);

	}
#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
	return (r + tmp);
}
