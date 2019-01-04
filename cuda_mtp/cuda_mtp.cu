/**
 * MTP 
 * djm34 2017-2018
 * krnlx 2018
 **/
 
#include <stdio.h>
#include <memory.h>


#include "lyra2/cuda_lyra2_vectors.h"
static uint32_t *h_MinNonces[16]; // this need to get fixed as the rest of that routine
static uint32_t *d_MinNonces[16];

__constant__ uint32_t pTarget[8];
__constant__ uint32_t pData[20]; // truncated data
__constant__ uint4 Elements[1];
uint4 * HBlock[16];
/*__device__*/ uint32_t *Header[16];
/*__device__*/ uint2 *buffer_a[16];

#define ARGON2_SYNC_POINTS 4
#define argon_outlen 32
#define argon_timecost 1
#define argon_memcost 4*1024*1024 // *1024 //32*1024*2 //1024*256*1 //2Gb
#define argon_lanes 4
#define argon_threads 1
#define argon_hashlen 80
#define argon_version 19
#define argon_type 0 // argon2d
#define argon_pwdlen 80 // hash and salt lenght
#define argon_default_flags 0 // hmm not sure
#define argon_segment_length argon_memcost/(argon_lanes * ARGON2_SYNC_POINTS)
#define argon_lane_length argon_segment_length * ARGON2_SYNC_POINTS
#define TREE_LEVELS 20
#define ELEM_MAX 2048
#define gpu_thread 2
#define gpu_shared 128
#define kernel1_thread 64
#define mtp_L 64
#define TPB52 32
#define TPB30 160
#define TPB20 160

__constant__ const uint2 blakeInit[8] =
{
	{ 0xf2bdc948UL, 0x6a09e667UL },
	{ 0x84caa73bUL, 0xbb67ae85UL },
	{ 0xfe94f82bUL, 0x3c6ef372UL },
	{ 0x5f1d36f1UL, 0xa54ff53aUL },
	{ 0xade682d1UL, 0x510e527fUL },
	{ 0x2b3e6c1fUL, 0x9b05688cUL },
	{ 0xfb41bd6bUL, 0x1f83d9abUL },
	{ 0x137e2179UL, 0x5be0cd19UL }
};

__constant__ const uint2 blakeFinal[8] =
{
	{ 0xf2bdc928UL, 0x6a09e667UL },
	{ 0x84caa73bUL, 0xbb67ae85UL },
	{ 0xfe94f82bUL, 0x3c6ef372UL },
	{ 0x5f1d36f1UL, 0xa54ff53aUL },
	{ 0xade682d1UL, 0x510e527fUL },
	{ 0x2b3e6c1fUL, 0x9b05688cUL },
	{ 0xfb41bd6bUL, 0x1f83d9abUL },
	{ 0x137e2179UL, 0x5be0cd19UL }
};

__constant__ const uint2 blakeIV[8] =
{
	{ 0xf3bcc908UL, 0x6a09e667UL },
	{ 0x84caa73bUL, 0xbb67ae85UL },
	{ 0xfe94f82bUL, 0x3c6ef372UL },
	{ 0x5f1d36f1UL, 0xa54ff53aUL },
	{ 0xade682d1UL, 0x510e527fUL },
	{ 0x2b3e6c1fUL, 0x9b05688cUL },
	{ 0xfb41bd6bUL, 0x1f83d9abUL },
	{ 0x137e2179UL, 0x5be0cd19UL }
};

//6a09e667f2bdc918 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179
__constant__ const uint2 blakeInit2[8] =
{
	{ 0xf2bdc918UL, 0x6a09e667UL },
	{ 0x84caa73bUL, 0xbb67ae85UL },
	{ 0xfe94f82bUL, 0x3c6ef372UL },
	{ 0x5f1d36f1UL, 0xa54ff53aUL },
	{ 0xade682d1UL, 0x510e527fUL },
	{ 0x2b3e6c1fUL, 0x9b05688cUL },
	{ 0xfb41bd6bUL, 0x1f83d9abUL },
	{ 0x137e2179UL, 0x5be0cd19UL }
};


__device__ __forceinline__
uint64_t ROTR64X(const uint64_t value, const int offset) {
	uint2 result;
	const uint2 tmp = vectorize(value);

	if (offset == 8) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x4321);
		result.y = __byte_perm(tmp.y, tmp.x, 0x4321);
	}
	else if (offset == 16) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x5432);
		result.y = __byte_perm(tmp.y, tmp.x, 0x5432);
	}
	else if (offset == 24) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x6543);
		result.y = __byte_perm(tmp.y, tmp.x, 0x6543);
	}
	else if (offset < 32) {
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
	}
	else {
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
	}
	return devectorize(result);
}

__constant__ static const uint8_t blake2b_sigma[12][16] =
{
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};


/*
#define GS(a,b,c,d,e,f) \
{ \
v[a] +=   v[b] + m[e]; \
v[d] = eorswap32(v[d] , v[a]); \
v[c] += v[d]; \
v[b] = ROR2(v[b] ^ v[c], 24); \
v[a] += v[b] + m[f]; \
v[d] = ROR16(v[d] ^ v[a]); \
v[c] += v[d]; \
v[b] = ROR2(v[b] ^ v[c], 63); \
}
*/


#define GS(a,b,c,d,e,f) \
   { \
     v[a] +=   v[b] + m[e]; \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + m[f]; \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 


#define ROUND0\
  { \
    GS(0,4,8,12,0,1); \
    GS(1,5,9,13,2,3 ); \
    GS(2,6,10,14,4,5); \
    GS(3,7,11,15,6,7); \
    GS(0,5,10,15,8,9); \
    GS(1,6,11,12,10,11); \
    GS(2,7,8,13,12,13); \
    GS(3,4,9,14,14,15); \
  }

#define ROUND1\
  { \
    GS(0,4,8,12,14,10); \
    GS(1,5,9,13,4,8 ); \
    GS(2,6,10,14,9,15); \
    GS(3,7,11,15,13,6); \
    GS(0,5,10,15,1,12); \
    GS(1,6,11,12,0,2); \
    GS(2,7,8,13,11,7); \
    GS(3,4,9,14,5,3); \
  }

#define ROUND2\
  { \
    GS(0,4,8,12,11,8); \
    GS(1,5,9,13,12,0 ); \
    GS(2,6,10,14,5,2); \
    GS(3,7,11,15,15,13); \
    GS(0,5,10,15,10,14); \
    GS(1,6,11,12,3,6); \
    GS(2,7,8,13,7,1); \
    GS(3,4,9,14,9,4); \
  }

#define ROUND3\
  { \
    GS(0,4,8,12,7,9); \
    GS(1,5,9,13,3,1 ); \
    GS(2,6,10,14,13,12); \
    GS(3,7,11,15,11,14); \
    GS(0,5,10,15,2,6); \
    GS(1,6,11,12,5,10); \
    GS(2,7,8,13,4,0); \
    GS(3,4,9,14,15,8); \
  }

#define ROUND4\
  { \
    GS(0,4,8,12,9,0); \
    GS(1,5,9,13,5,7 ); \
    GS(2,6,10,14,2,4); \
    GS(3,7,11,15,10,15); \
    GS(0,5,10,15,14,1); \
    GS(1,6,11,12,11,12); \
    GS(2,7,8,13,6,8); \
    GS(3,4,9,14,3,13); \
  }

#define ROUND5\
  { \
    GS(0,4,8,12,2,12); \
    GS(1,5,9,13,6,10 ); \
    GS(2,6,10,14,0,11); \
    GS(3,7,11,15,8,3); \
    GS(0,5,10,15,4,13); \
    GS(1,6,11,12,7,5); \
    GS(2,7,8,13,15,14); \
    GS(3,4,9,14,1,9); \
  }

#define ROUND6\
  { \
    GS(0,4,8,12,12,5); \
    GS(1,5,9,13,1,15 ); \
    GS(2,6,10,14,14,13); \
    GS(3,7,11,15,4,10); \
    GS(0,5,10,15,0,7); \
    GS(1,6,11,12,6,3); \
    GS(2,7,8,13,9,2); \
    GS(3,4,9,14,8,11); \
  }


#define ROUND7\
  { \
    GS(0,4,8,12,13,11); \
    GS(1,5,9,13,7,14 ); \
    GS(2,6,10,14,12,1); \
    GS(3,7,11,15,3,9); \
    GS(0,5,10,15,5,0); \
    GS(1,6,11,12,15,4); \
    GS(2,7,8,13,8,6); \
    GS(3,4,9,14,2,10); \
  }


#define ROUND8\
  { \
    GS(0,4,8,12,6,15); \
    GS(1,5,9,13,14,9 ); \
    GS(2,6,10,14,11,3); \
    GS(3,7,11,15,0,8); \
    GS(0,5,10,15,12,2); \
    GS(1,6,11,12,13,7); \
    GS(2,7,8,13,1,4); \
    GS(3,4,9,14,10,5); \
  }

#define ROUND9\
  { \
    GS(0,4,8,12,10,2); \
    GS(1,5,9,13,8,4 ); \
    GS(2,6,10,14,7,6); \
    GS(3,7,11,15,1,5); \
    GS(0,5,10,15,15,11); \
    GS(1,6,11,12,9,14); \
    GS(2,7,8,13,3,12); \
    GS(3,4,9,14,13,0); \
  }

#define ROUND10\
  { \
    GS(0,4,8,12,0,1); \
    GS(1,5,9,13,2,3 ); \
    GS(2,6,10,14,4,5); \
    GS(3,7,11,15,6,7); \
    GS(0,5,10,15,8,9); \
    GS(1,6,11,12,10,11); \
    GS(2,7,8,13,12,13); \
    GS(3,4,9,14,14,15); \
  }

#define ROUND11\
  { \
    GS(0,4,8,12,14,10); \
    GS(1,5,9,13,4,8 ); \
    GS(2,6,10,14,9,15); \
    GS(3,7,11,15,13,6); \
    GS(0,5,10,15,1,12); \
    GS(1,6,11,12,0,2); \
    GS(2,7,8,13,11,7); \
    GS(3,4,9,14,5,3); \
  }



static __device__ __forceinline__ uint2 eorswap32(uint2 u, uint2 v) {
	uint2 result;
	result.y = u.x ^ v.x;
	result.x = u.y ^ v.y;
	return result;
}

static __device__ __forceinline__ uint64_t eorswap64(uint64_t u, uint64_t v) {
	return ROTR64X(u^v, 32);
}

__device__ __forceinline__ static int blake2b_compress2_256(uint64_t *hash, const uint64_t *hzcash, const uint64_t block[16], const uint32_t len)
{
	uint64_t m[16];
	uint64_t v[16];
#pragma unroll
	for (int i = 0; i < 16; ++i)
		m[i] = block[i];
#pragma unroll
	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = devectorize(blakeIV[0]);
	v[9] = devectorize(blakeIV[1]);
	v[10] = devectorize(blakeIV[2]);
	v[11] = devectorize(blakeIV[3]);
	v[12] = devectorize(blakeIV[4]);
	v[12] ^= len;
	v[13] = devectorize(blakeIV[5]);
	v[14] = ~devectorize(blakeIV[6]);
	v[15] = devectorize(blakeIV[7]);



#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 

#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

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
#pragma unroll
	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}

__device__ __forceinline__ static int blake2b_compress2c_256(uint64_t *hash, const uint64_t *hzcash, const uint64_t block[16], const uint32_t len)
{
	uint64_t m[16];
	uint64_t v[16];
#pragma unroll
	//	for (int i = 0; i < 16; ++i)
	//		m[i] = block[i];
	for (int i = 0; i < 4; ++i)
		m[i] = block[i];
	for (int i = 4; i < 16; ++i)
		m[i] = 0;

#pragma unroll
	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);


	v[8] = devectorize(blakeIV[0]);
	v[9] = devectorize(blakeIV[1]);
	v[10] = devectorize(blakeIV[2]);
	v[11] = devectorize(blakeIV[3]);
	v[12] = devectorize(blakeIV[4]);
	v[12] ^= len;
	v[13] = devectorize(blakeIV[5]);
	v[14] = ~devectorize(blakeIV[6]);
	v[15] = devectorize(blakeIV[7]);


#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 

#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

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
#pragma unroll
	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}



__device__ __forceinline__ static int blake2b_compress2b(uint64_t *hzcash, const uint64_t * __restrict__ m, const uint32_t len, int last)
{

//	uint64_t m[16];
	uint64_t v[16];

	const uint64_t blakeIV_[8] = {
		0x6a09e667f3bcc908ULL,
		0xbb67ae8584caa73bULL,
		0x3c6ef372fe94f82bULL,
		0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL,
		0x9b05688c2b3e6c1fULL,
		0x1f83d9abfb41bd6bULL,
		0x5be0cd19137e2179ULL
	};
/*
#pragma unroll
	for (int i = 0; i < 16; ++i)
		m[i] = block[i];
*/
#pragma unroll
	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];




	v[8] = blakeIV_[0];
	v[9] = blakeIV_[1];
	v[10] = blakeIV_[2];
	v[11] = blakeIV_[3];
	v[12] = blakeIV_[4];
	v[12] ^= len;
	v[13] = blakeIV_[5];
	v[14] = last ? ~blakeIV_[6] : blakeIV_[6];
	v[15] = blakeIV_[7];

	/*
	if(!thread){
	printf("0x%llxULL\n", v[12]);
	}*/

#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 
#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

#define H(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
  } 

#define ROUNDF  \
  { \
    G(11,0, 0,4,8,12); \
    G(11,1, 1,5,9,13); \
    G(11,2, 2,6,10,14); \
    G(11,3, 3,7,11,15); \
    if(!last){\
    G(11,4, 0,5,10,15); \
    G(11,5, 1,6,11,12); \
    G(11,6, 2,7,8,13); \
    G(11,7, 3,4,9,14); \
    }else{\
    H(11,4, 0,5,10,15); \
    H(11,5, 1,6,11,12); \
    H(11,6, 2,7,8,13); \
    H(11,7, 3,4,9,14); \
    }\
  }


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
//	ROUNDF;
	/*
	ROUND0;
	ROUND1;
	ROUND2;
	ROUND3;
	ROUND4;
	ROUND5;
	ROUND6;
	ROUND7;
	ROUND8;
	ROUND9;
	ROUND10;
	ROUND11;
	*/

	for (int i = 0; i < 8; ++i)
		hzcash[i] ^= v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}




__device__ __forceinline__ void prefetch(void* addr)
{
	asm volatile("prefetch.global.L1 [%0];" : : "l"(addr));
}

__device__ __forceinline__ void prefetch2(void* addr)
{
	asm volatile("prefetch.global.L2 [%0];" : : "l"(addr));
}

__device__ __forceinline__ void prefetchu(void* addr)
{
	asm volatile("prefetchu.L1 [%0];" : : "l"(addr));
}

#define TPB_MTP 320

__forceinline__ __device__ unsigned lane_id()
{
	unsigned ret;
	asm volatile ("mov.u32 %0, %laneid;" : "=r"(ret));
	return ret;
}

__forceinline__ __device__ unsigned warp_id()
{
	// this is not equal to threadIdx.x / 32
	unsigned ret;
	asm volatile ("mov.u32 %0, %warpid;" : "=r"(ret));
	return ret;
}



__device__ __forceinline__ uint32_t load32(uint32_t * const addr)
{
	uint32_t x;
	asm volatile("ld.global.cg.u32 %0, [%1];" : "=r"(x) : "l"(addr));
	return x;
}


#define FARLOAD(x) far[warp][(x)*(8+SHR_OFF) + lane]
#define FARSTORE(x) far[warp][lane*(8+SHR_OFF) + (x)]
#define SHR_OFF 1


__global__ __launch_bounds__(TPB_MTP, 1)
void mtp_yloop(uint32_t thr_id, uint32_t threads, uint32_t startNounce, const uint4  * __restrict__ DBlock,
	uint32_t * __restrict__ SmallestNonce)
{
	unsigned mask = __activemask();
//	mask = 0xffffffff;
//	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint32_t NonceNumber = 1;  // old
	uint32_t ThreadNumber = 1;
	uint32_t event_thread = (blockDim.x * blockIdx.x + threadIdx.x); //thread / ThreadNumber;
	uint32_t NonceIterator = startNounce + event_thread;
	int lane = lane_id()%8;
	int warp = threadIdx.x / 8;;//warp_id();
	__shared__ __align__(128) ulonglong2 far[TPB_MTP / 8][8 * (8 + SHR_OFF)];
	__shared__ __align__(32) uint32_t farIndex[TPB_MTP / 8][8];

	if (event_thread < threads)
	{

		const ulonglong2 *	 __restrict__ GBlock = &((ulonglong2*)DBlock)[0];
		uint8 YLocal;

		ulong8 DataChunk[2] = { 0 };
		/*
		((uint4*)DataChunk)[0] = ((uint4*)pData)[0];
		((uint4*)DataChunk)[1] = ((uint4*)pData)[1];

		((uint4*)DataChunk)[2] = ((uint4*)pData)[2];
		((uint4*)DataChunk)[3] = ((uint4*)pData)[3];
		*/

		((uint2x4 *)DataChunk)[0] = ((uint2x4 *)pData)[0];
		((uint2x4 *)DataChunk)[1] = ((uint2x4 *)pData)[1];
		//((uint2x4 *)DataChunk)[0] =  __ldg4(&((uint2x4 *)pData)[0]);
		//((uint2x4 *)DataChunk)[1] = __ldg4(&((uint2x4 *)pData)[1]);

		((uint4*)DataChunk)[4] = ((uint4*)pData)[4];
		((uint4*)DataChunk)[5] = ((uint4*)Elements)[0];

		((uint16*)DataChunk)[1].hi.s0 = NonceIterator;

		blake2b_compress2_256((uint64_t*)&YLocal, (uint64_t*)blakeFinal, (uint64_t*)DataChunk, 100);


		bool init_blocks;
		uint32_t unmatch_block;
		//		uint32_t localIndex;
		init_blocks = false;
		unmatch_block = 0;

#pragma unroll 1
		for (int j = 1; j <= mtp_L; j++)
		{

			//				localIndex = YLocal.s0%(argon_memcost);
			//				localIndex = YLocal.s0 & 0x3FFFFF;
//			uint64_t farIndex[8];


			#pragma unroll
			for (int t = 0; t<2; t++) {
				ulonglong2 *D = (ulonglong2*)&YLocal;
				FARLOAD(t + 6) = D[t];
				
			}
				farIndex[warp][lane] = YLocal.s0 & 0x3FFFFF;
			__syncwarp(mask);

			ulong8 DataChunk[2];
			uint32_t len = 0;

			uint16 DataTmp; uint2 * blake_init = (uint2*)&DataTmp;
			for (int i = 0; i<8; i++)blake_init[i] = blakeFinal[i];

//			uint8 part;


			#pragma unroll 1
			for (int i = 0; i < 9; i++) {
				int last = (i == 8);
				#pragma unroll
				for (int t = 0; t<2; t++) {
					ulonglong2 *D = (ulonglong2*)&YLocal;
					D[t] = FARLOAD(t + 6);
				}


				len += last ? 32 : 128;

				//if(!last)
				{


					#pragma unroll 
					for (int t = 0; t<8; t++) {
						
						ulonglong2 *farP = (ulonglong2*)&GBlock[farIndex[warp][t] * 64 + 0 + 8 * i + 0];

						far[warp][lane*(8 + SHR_OFF) + (t)] = (last) ? make_ulonglong2(0,0) : farP[lane];
					}

					__syncwarp(mask);
				}

				#pragma unroll
				for (int t = 0; t<6; t++) {
					ulonglong2 *D = (ulonglong2*)DataChunk;
					D[t + 2] = (FARLOAD(t));
				}
				((uint16*)DataChunk)[0].lo = YLocal;

			//	uint16 DataTmp2;
				blake2b_compress2b(/*(uint64_t*)&DataTmp2,*/ (uint64_t*)&DataTmp, (uint64_t*)DataChunk, len, last);
			//	DataTmp = DataTmp2;


			}

			YLocal = DataTmp.lo;
		}



		if (YLocal.s7 <= pTarget[7])

		{
			atomicMin(&SmallestNonce[0], NonceIterator);

		}

	}
}



__host__
void mtp_cpu_init(int thr_id, uint32_t threads)
{
	cudaSetDevice(device_map[thr_id]);
	// just assign the device pointer allocated in main loop


	cudaMalloc((void**)&HBlock[thr_id], 256 * argon_memcost * sizeof(uint32_t));
	cudaMalloc(&d_MinNonces[thr_id], sizeof(uint32_t));
	cudaMallocHost(&h_MinNonces[thr_id], sizeof(uint32_t));
	cudaMalloc(&Header[thr_id], sizeof(uint32_t) * 8);
	cudaMalloc(&buffer_a[thr_id], 4194304 * 64);
}


__host__
void mtp_setBlockTarget(int thr_id, const void* pDataIn, const void *pTargetIn, const void * zElement)
{
	cudaSetDevice(device_map[thr_id]);

	cudaMemcpyToSymbol(pData, pDataIn, 80, 0, cudaMemcpyHostToDevice);
	cudaMemcpyToSymbol(pTarget, pTargetIn, 32, 0, cudaMemcpyHostToDevice);
	cudaMemcpyToSymbol(Elements, zElement, 4 * sizeof(uint32_t), 0, cudaMemcpyHostToDevice);

}

__host__
void mtp_fill(uint32_t dev_id, const uint64_t *Block, uint32_t offset, uint32_t datachunk)
{
	cudaSetDevice(device_map[dev_id]);
	uint4 *Blockptr = &HBlock[dev_id][offset * 64 * datachunk];
	cudaError_t err = cudaMemcpyAsync(Blockptr, Block, datachunk * 256 * sizeof(uint32_t), cudaMemcpyHostToDevice);

	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}

}

__host__
uint32_t mtp_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce)
{
	cudaSetDevice(device_map[thr_id]);
	uint32_t result = UINT32_MAX;
	cudaMemset(d_MinNonces[thr_id], 0xff, sizeof(uint32_t));
	int dev_id = device_map[thr_id % MAX_GPUS];

	uint32_t tpb = TPB_MTP; //TPB52;

	dim3 gridyloop(threads / tpb);
	dim3 blockyloop(tpb);

	mtp_yloop << < gridyloop, blockyloop >> >(thr_id, threads, startNounce, HBlock[thr_id], d_MinNonces[thr_id]);


	cudaMemcpy(h_MinNonces[thr_id], d_MinNonces[thr_id], sizeof(uint32_t), cudaMemcpyDeviceToHost);

	result = *h_MinNonces[thr_id];
	return result;

}




__device__ static int blake2b_compress4x(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len, int last)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	uint64_t xv = last ? (uint64_t)-1 : 0;
	uint2 xv2 = vectorize(xv);
	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = blakeIV[6] ^ xv2;
	v[15] = blakeIV[7];

	uint64_t *d = (uint64_t*)v;

	/*
	if(!thread){
	for(int i=0;i<16;i++)
	printf("%lx ",v[i]);
	printf("\n");
	}
	*/

#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + m[blake2b_sigma[r][2*i+0]]; \
     v[d] = eorswap32(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROR2(v[b] ^ v[c], 24); \
     v[a] += v[b] + m[blake2b_sigma[r][2*i+1]]; \
     v[d] = ROR16(v[d] ^ v[a]); \
     v[c] += v[d]; \
     v[b] = ROR2(v[b] ^ v[c], 63); \
  } 
#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	/*
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);
	*/
	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];


#undef G
#undef ROUND
	return 0;
}



__device__ __forceinline__ uint32_t index_alpha(const uint32_t pass, const uint32_t slice, const uint32_t index,
	uint32_t pseudo_rand,
	int same_lane, const uint32_t ss, const uint32_t ss1) {
	/*
	* Pass 0:
	*      This lane : all already finished segments plus already constructed
	* blocks in this segment
	*      Other lanes : all already finished segments
	* Pass 1+:
	*      This lane : (SYNC_POINTS - 1) last segments plus already constructed
	* blocks in this segment
	*      Other lanes : (SYNC_POINTS - 1) last segments
	*/
	uint32_t reference_area_size;
	uint64_t relative_position;
	uint32_t start_position, absolute_position;
	uint32_t lane_length = 1048576;
	uint32_t segment_length = 262144;
	uint32_t lanes = 4;

	if (0 == pass) {
		/* First pass */
		if (0 == slice) {
			/* First slice */
			reference_area_size =
				index - 1; /* all but the previous */
		}
		else {
			if (same_lane) {
				/* The same lane => add current segment */
				reference_area_size =
					ss +
					index - 1;
			}
			else {
				reference_area_size =
					ss +
					((index == 0) ? (-1) : 0);
			}
		}
	}
	else {
		/* Second pass */
		if (same_lane) {
			reference_area_size = lane_length -
				segment_length + index -
				1;
		}
		else {
			reference_area_size = lane_length -
				segment_length +
				((index == 0) ? (-1) : 0);
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	* relative position */
	relative_position = pseudo_rand;
	//__syncwarp();
	relative_position = _HIDWORD(relative_position * relative_position);//relative_position * relative_position >> 32;
																		//printf("%x %lx %x %d\n",(uint32_t)__mulhi(pseudo_rand,pseudo_rand), relative_position, pseudo_rand, threadIdx.x);

																		//	relative_position = MAKE_ULONGLONG(__mulhi((int)pseudo_rand,(int)pseudo_rand),0);
																		/*
																		unsigned int a, b, prod_hi, prod_lo;
																		unsigned long long int prod;
																		a = 0x31415926;
																		b = 0x53589793;
																		prod_lo = a * b;
																		prod_hi = __umulhi(a, b);
																		prod = (unsigned long long int)a * b;
																		printf ("prod_hi_lo = %08x_%08x  prod=%016llx\n", prod_hi, prod_lo, prod);
																		*/

	relative_position = reference_area_size - 1 -
		_HIDWORD(reference_area_size * relative_position);
	//(reference_area_size * relative_position >> 32);

	/* 1.2.5 Computing starting position */
	start_position = 0;

	if (0 != pass) {
		start_position = (slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (ss1);
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + relative_position) & 0xFFFFF;
	//                        lane_length; /* absolute position */
	return absolute_position;
}

struct mem_blk {
	uint64_t v[128];
};


/*

__device__ __forceinline__ void copy_block(mem_blk *dst, const mem_blk *src) {
#pragma unroll
for(int i=0;i<128;i++)
dst->v[i]=src->v[i];
}

__device__ __forceinline__ void xor_block(mem_blk *dst, const mem_blk *src) {
int i;
#pragma unroll
for (i = 0; i < 128; ++i) {
dst->v[i] ^= src->v[i];
}
}

*/

__device__ __forceinline__ void copy_block(mem_blk *dst, const mem_blk *src) {
	dst->v[threadIdx.x] = src->v[threadIdx.x];
	dst->v[threadIdx.x + 32] = src->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] = src->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] = src->v[threadIdx.x + 96];

}

__device__ __forceinline__ void xor_block(mem_blk *dst, const mem_blk *src) {
	dst->v[threadIdx.x] ^= src->v[threadIdx.x];
	dst->v[threadIdx.x + 32] ^= src->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] ^= src->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] ^= src->v[threadIdx.x + 96];
}
__device__ __forceinline__ uint64_t fBlaMka(uint64_t x, uint64_t y) {
	const uint64_t m = UINT64_C(0xFFFFFFFF);
	//    const uint64_t xy = (x & m) * (y & m);
	const uint64_t xy = ((uint64_t)_LODWORD(x) * (uint64_t)_LODWORD(y));
	return x + y + 2 * xy;
}

#define G(a, b, c, d)                                                          \
    do {                                                                       \
        a = fBlaMka(a, b);                                                     \
        d = SWAPDWORDS(d ^ a);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = ROTR64X(b ^ c, 24);                                                 \
        a = fBlaMka(a, b);                                                     \
        d = ROTR64X(d ^ a, 16);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = ROTR64X(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)                                 \
    do {                                                                       \
        G(v0, v4, v8, v12);                                                    \
        G(v1, v5, v9, v13);                                                    \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8, v13);                                                    \
        G(v3, v4, v9, v14);                                                    \
    } while ((void)0, 0)

__device__ __forceinline__ void xor_copy_block(mem_blk *dst, const mem_blk *src, const mem_blk *src1) {
	dst->v[threadIdx.x] = src->v[threadIdx.x] ^ src1->v[threadIdx.x];
	dst->v[threadIdx.x + 32] = src->v[threadIdx.x + 32] ^ src1->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] = src->v[threadIdx.x + 64] ^ src1->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] = src->v[threadIdx.x + 96] ^ src1->v[threadIdx.x + 96];
}

__device__ __forceinline__ void dup_xor_copy_block(mem_blk *dst, mem_blk *dst1, const mem_blk *src, const mem_blk *src1) {
	dst1->v[threadIdx.x] = dst->v[threadIdx.x] = src->v[threadIdx.x] ^ src1->v[threadIdx.x];
}

__device__ __forceinline__ void fill_block_withIndex(const mem_blk *prev_block, const mem_blk *ref_block,
	mem_blk *next_block, int with_xor, uint32_t block_header[8], uint32_t index) {
	__shared__ mem_blk blockR;
	__shared__ mem_blk block_tmp;
	int tid = threadIdx.x;
	uint32_t TheIndex[2] = { 0,index };
	unsigned i;

	copy_block(&blockR, ref_block);

	xor_block(&blockR, prev_block);

	copy_block(&block_tmp, &blockR);

	//dup_xor_copy_block(&block_tmp, &blockR, ref_block, prev_block);

	if (with_xor) {
		/* Saving the next block contents for XOR over: */
		xor_block(&block_tmp, next_block);
		/* Now blockR = ref_block + prev_block and
		block_tmp = ref_block + prev_block + next_block */
	}
	//	blockR.v[16] = ((uint64_t*)block_header)[0];
	//	blockR.v[17] = ((uint64_t*)block_header)[1];
	if (!tid) {
		//	memcpy(&blockR.v[14], TheIndex,  sizeof(uint64_t)); //index here
		blockR.v[14] = MAKE_ULONGLONG(TheIndex[0], TheIndex[1]);
		//	memcpy(&blockR.v[16], (uint64_t*)block_header, 2 * sizeof(uint64_t));
		//	memcpy(&blockR.v[18], (uint64_t*)(block_header + 4), 2 * sizeof(uint64_t));

		//printf("block header in cpu %llx %llx %llx %llx\n", blockR.v[15], blockR.v[16], blockR.v[17], blockR.v[18]);
	}

	uint32_t *bl = (uint32_t*)&blockR.v[16];
	//if(tid<24 && tid >=16)
	//	bl[tid-16]=block_header[tid-16];

	if (!tid)
		for (int i = 0; i<8; i++)
			bl[i] = block_header[i];


	__syncwarp();
	//__syncthreads();
	//if(tid<32)
	{

		int i = tid;
		int y = (tid >> 2) << 4;
		int x = tid & 3;
		/*
		uint64_t t[16];
		for(int i=0;i<16;i++)
		t[i]= blockR.v[y+i];
		*/

		G(blockR.v[y + x], blockR.v[y + 4 + x], blockR.v[y + 8 + x], blockR.v[y + 12 + x]);
		G(blockR.v[y + x], blockR.v[y + 4 + ((1 + x) & 3)], blockR.v[y + 8 + ((2 + x) & 3)], blockR.v[y + 12 + ((3 + x) & 3)]);
		//printf("%d %d %d %d\n",x,4+((1 + x)&3), 8+((2 + x)&3), 12 +((3 + x)&3));
		//return;

		/*
		BLAKE2_ROUND_NOMSG(
		blockR.v[y], blockR.v[y + 1], blockR.v[y + 2],
		blockR.v[y + 3], blockR.v[y + 4], blockR.v[y + 5],
		blockR.v[y + 6], blockR.v[y + 7], blockR.v[y + 8],
		blockR.v[y + 9], blockR.v[y + 10], blockR.v[y + 11],
		blockR.v[y + 12], blockR.v[y + 13], blockR.v[y + 14],
		blockR.v[y + 15]);
		*/
		/*

		BLAKE2_ROUND_NOMSG(
		t[0], t[1], t[2], t[3],
		t[4], t[5], t[6], t[7],
		t[8], t[9], t[10], t[11],
		t[12], t[13], t[14], t[15]);


		G(v0, v4, v8, v12);                                                    \
		G(v1, v5, v9, v13);                                                    \
		G(v2, v6, v10, v14);                                                   \
		G(v3, v7, v11, v15);                                                   \
		G(v0, v5, v10, v15);                                                   \
		G(v1, v6, v11, v12);                                                   \
		G(v2, v7, v8, v13);                                                    \
		G(v3, v4, v9, v14);



		for(int i=0;i<16;i++)
		blockR.v[y+i] = t[i];
		*/
	}
	__syncwarp();
	//__syncwarp();
	//__syncthreads();
	//if(!threadIdx.x){
	//	for (i = 0; i < 8; i++) {
	//if(tid<32)
	{
		/*
		int i=tid;
		int y=tid << 1;
		*/

		int i = tid;
		int y = (tid >> 2) << 1;
		int x = tid & 3;
		int a = ((x) >> 1) * 16;
		int b = x & 1;

		/*
		uint64_t t[16];
		for(int i=0;i<8;i++)
		t[i*2]= blockR.v[y+i*16];

		for(int i=0;i<8;i++)
		t[i*2+1]= blockR.v[y+i*16+1];
		*/

		int a1 = (((x + 1) & 3) >> 1) * 16;
		int b1 = (x + 1) & 1;

		int a2 = (((x + 2) & 3) >> 1) * 16;
		int b2 = (x + 2) & 1;

		int a3 = (((x + 3) & 3) >> 1) * 16;
		int b3 = (x + 3) & 1;

		G(blockR.v[y + b + a], blockR.v[y + 32 + b + a], blockR.v[y + 64 + b + a], blockR.v[y + 96 + b + a]);
		G(blockR.v[y + b + a], blockR.v[y + 32 + b1 + a1], blockR.v[y + 64 + b2 + a2], blockR.v[y + 96 + a3 + b3]);
		//printf("%d %d %d %d\n",b+a,32+b1+a1, 64+b2+a2, 96+b3+a3);
		//return;

		/*
		BLAKE2_ROUND_NOMSG(
		blockR.v[y], blockR.v[y + 1], blockR.v[y + 16],
		blockR.v[y + 17], blockR.v[y + 32], blockR.v[y + 33],
		blockR.v[y + 48], blockR.v[y + 49], blockR.v[y + 64],
		blockR.v[y + 65], blockR.v[y + 80], blockR.v[y + 81],
		blockR.v[y + 96], blockR.v[y + 97], blockR.v[y + 112],
		blockR.v[y + 113]);
		*/
		/*
		BLAKE2_ROUND_NOMSG(
		t[0], t[1], t[2], t[3],
		t[4], t[5], t[6], t[7],
		t[8], t[9], t[10], t[11],
		t[12], t[13], t[14], t[15]);
		*/
		/*
		for(int i=0;i<8;i++)
		blockR.v[y+i*16] = t[i*2];

		for(int i=0;i<8;i++)
		blockR.v[y+i*16+1] = t[i*2+1];
		*/
	}
	__syncwarp();
	//}
	//	__syncthreads();
	//	xor_block(&block_tmp, &blockR);
	//	copy_block(next_block, &block_tmp);
	xor_copy_block(next_block, &block_tmp, &blockR);

	//xor_block(next_block, &blockR);
}

template <const uint32_t slice>
__global__ __launch_bounds__(128, 1)
void mtp_i(uint4  *  DBlock, uint32_t *block_header) {
	uint32_t prev_offset, curr_offset;
	//uint64_t pseudo_rand;
	uint64_t  ref_index, ref_lane;
	const uint32_t pass = 0;
	//uint32_t lane =threadIdx.x;
	uint32_t lane = blockIdx.x;
	const uint32_t lane_length = 1048576;
	const uint32_t segment_length = 262144;
	const uint32_t lanes = 4;
	uint32_t index;
	struct mem_blk * memory = (struct mem_blk *)DBlock;
	int tid = threadIdx.x;
	struct mem_blk *ref_block = NULL, *curr_block = NULL;
	uint32_t BH[8];
	uint32_t ss = slice * segment_length;
	uint32_t ss1 = (slice + 1) * segment_length;

	for (int i = 0; i<8; i++)
		BH[i] = block_header[i];

	uint32_t starting_index = 0;

	if ((0 == pass) && (0 == slice)) {
		starting_index = 2; /* we have already generated the first two blocks */
	}
	curr_offset = lane * lane_length +
		slice * segment_length + starting_index;

	if (0 == curr_offset % lane_length) {
		/* Last block in this lane */
		prev_offset = curr_offset + lane_length - 1;
	}
	else {
		/* Previous block */
		prev_offset = curr_offset - 1;
	}


	int truc = 0;
	uint64_t TheBlockIndex;
#pragma unroll 1
	for (int i = starting_index; i < segment_length;
		++i, ++curr_offset, ++prev_offset) {
		truc++;

		//if(!tid){
		/*1.1 Rotating prev_offset if needed */
		if (curr_offset & 0xFFFFF == 1) {
			prev_offset = curr_offset - 1;
		}

		/* 1.2 Computing the index of the reference block */
		/* 1.2.1 Taking pseudo-random value from the previous block */
		//	if(!threadIdx.x)
		//	__syncthreads();
		uint2  pseudo_rand2 = vectorize(memory[prev_offset].v[0]);
		//	__syncthreads();
		/* 1.2.2 Computing the lane of the reference block */
		ref_lane = ((pseudo_rand2.y)) & 3;

		if ((pass == 0) && (slice == 0)) {
			/* Can not reference other lanes yet */
			ref_lane = lane;
		}

		/* 1.2.3 Computing the number of possible reference block within the
		* lane.
		*/
		index = i;
		ref_index = index_alpha(pass, slice, index, pseudo_rand2.x,
			ref_lane == lane, ss, ss1);
		/* 2 Creating a new block */
		ref_block =
			memory + (ref_lane << 20) + ref_index;

		curr_block = memory + curr_offset;
		TheBlockIndex = (ref_lane << 20) + ref_index;

		fill_block_withIndex(memory + prev_offset, ref_block, curr_block, 0, BH, TheBlockIndex);

	}

}



__global__ void mtp_fc(uint32_t threads, uint4  *  DBlock, uint2 *a) {
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads) {
		struct mem_blk * memory = (struct mem_blk *)DBlock;
		const uint4 *    __restrict__ GBlock = &DBlock[0];
		uint32_t len = 0;
		uint2 DataTmp[8];
		for (int i = 0; i<8; i++)
			DataTmp[i] = blakeInit2[i];
		for (int i = 0; i < 8; i++) {
			//              len += (i&1!=0)? 32:128;
			len += 128;
			uint16 DataChunk[2];
			DataChunk[0].lo = ((uint8*)GBlock)[thread * 32 + 4 * i + 0];
			DataChunk[0].hi = ((uint8*)GBlock)[thread * 32 + 4 * i + 1];
			DataChunk[1].lo = ((uint8*)GBlock)[thread * 32 + 4 * i + 2];
			DataChunk[1].hi = ((uint8*)GBlock)[thread * 32 + 4 * i + 3];
			uint2 DataTmp2[8];
			blake2b_compress4x((uint2*)&DataTmp2, (uint2*)&DataTmp, (uint2*)DataChunk, len, i == 7);
			for (int i = 0; i<8; i++)DataTmp[i] = DataTmp2[i];
			//              DataTmp = DataTmp2;
			//                              if(thread == 1) printf("%x %x\n",DataChunk[0].lo.s0, DataTmp[0].x);;

		}
#pragma unroll
		for (int i = 0; i<2; i++)
			a[thread * 2 + i] = DataTmp[i];




	}
}



__host__ void get_tree(int thr_id, uint8_t* d) {
	cudaMemcpy(d, buffer_a[thr_id], sizeof(uint2) * 2 * 1048576 * 4, cudaMemcpyDeviceToHost);
}

__host__ void get_block(int thr_id, void* d, uint32_t index) {
	cudaMemcpy(d, &HBlock[thr_id][64 * index], sizeof(uint64_t) * 128, cudaMemcpyDeviceToHost);
}
__host__ void mtp_i_cpu(int thr_id, uint32_t *block_header) {


	cudaError_t err = cudaMemcpy(Header[thr_id], block_header, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}
	uint32_t tpb = 32;
	dim3 grid(4);
	dim3 block(tpb);
	//        for(int i=0;i<4;i++)
	//                mtp_i << <grid, block>> >(HBlock[thr_id],Header[thr_id],i);

	mtp_i<0> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<1> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<2> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<3> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();

	tpb = 256;
	dim3 grid2(1048576 * 4 / tpb);
	dim3 block2(tpb);
	mtp_fc << <grid2, block2 >> >(1048576 * 4, HBlock[thr_id], buffer_a[thr_id]);
	cudaDeviceSynchronize();
	/*
	tpb=256;
	dim3 grid3(1048576*4/tpb + 1);
	dim3 block3(tpb);
	mtp_reduce <<<grid3, block3>>>(1048576*4, buffer_a[thr_id], buffer_b[thr_id]);
	*/
}

__host__
void mtp_fill_1b(int thr_id, uint64_t *Block, uint32_t block_nr)
{
	uint4 *Blockptr = &HBlock[thr_id][block_nr * 64];
	cudaError_t err = cudaMemcpy(Blockptr, Block, 256 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}

}