/**
 * Argon2 based on 
 * djm34 2017
 **/

#include <stdio.h>
#include <memory.h>

#include "cuda_sha256_helper.cuh" // sha256 transform

static uint32_t *h_GNonces[16]; // this need to get fixed as the rest of that routine
static uint32_t *d_GNonces[16];

static uint32_t *h_MinNonces[16]; // this need to get fixed as the rest of that routine
static uint32_t *d_MinNonces[16];

__constant__ uint32_t pTarget[8];
__constant__ uint32_t pData[8]; // truncated data
__constant__ uint2 initMess[25];
__constant__ uint4 Elements[2];
uint4 * HBlock;
uint4 * HSmallBlock;
uint2 * HBlockHistory;
//uint4 * Elements;
uint4 * YElements;


#define ARGON2_SYNC_POINTS 4
#define argon_outlen 32
#define argon_timecost 1
#define argon_memcost 2*1024*1024 //32*1024*2 //1024*256*1 //2Gb
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
#define mtp_L 70
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

static __device__ __forceinline__ uint2 eorswap32(uint2 u, uint2 v) {
	uint2 result;
	result.y = u.x ^ v.x;
	result.x = u.y ^ v.y;
	return result;
}

__device__ static uint2 fBlaMka(uint2 x, uint2 y)
{ // hmm
uint64_t ret = devectorize(x+y);
uint64_t xy = (uint64_t)x.x * (uint64_t)y.x;
xy <<= 1;
return (vectorize(ret+xy));
}



__device__ static int blake2b_compress1(uint2 *hash, const uint2 *hzcash, const uint2 block[16])
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = make_uint2(128, 0) ^ blakeIV[4];
	v[13] = blakeIV[5];						 // t[1] 0 or 1
	v[14] = blakeIV[6];						 //
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}

__device__ static int blake2b_compress2(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = ~blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}

__device__ static int blake2b_compress2_256(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = ~blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}


__device__ static int blake2b_compress2c(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);


	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = ~blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}

__device__ static int blake2b_compress2c_256(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);


	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = ~blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}



__device__ static int blake2b_compress2b(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];


	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];


#undef G
#undef ROUND
	return 0;
}

__device__ static int blake2b_compress2b_256(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];


	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];


#undef G
#undef ROUND
	return 0;
}


__device__ static int blake2b_compress3(const uint2 *hzcash, uint2 block[16], const uint32_t len)
{
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = ~blakeIV[6];
	v[15] = blakeIV[7];

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
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		block[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}



__device__ static void initialize_hash(uint32_t Nonce, uint2 * initHash)
{
	// 2 blakes round to digest the initial message
	uint2 first[8];
	uint2 hash1[16];// = {{argon_lanes,argon_outlen},{},}
	uint2 zero2 = { 0,0 };
	for (int i = 0; i<16; i++)
		hash1[i] = initMess[i];
	hash1[13].x = Nonce;

	blake2b_compress1(first, blakeInit, hash1);

#pragma unroll
	for (int i = 0; i<9; i++)
		hash1[i] = initMess[i + 16];

	hash1[7].y = Nonce;

#pragma unroll
	for (int i = 0; i < 7; i++)
		hash1[i + 9] = zero2;
	blake2b_compress2(initHash, first, hash1, 200);
}

__device__ static void blake2b_long1024(uint2* __restrict__ blockhash_byte, uint32_t offset, uint2* blockHash, uint32_t mod1, uint32_t mod2)
{

	uint2 /*__align__(32)*/ first[16] = { 0 };
	uint2 /*__align__(32)*/ hash1[16] = { 0 };
	for (int i = 0; i < 10; i++)
		hash1[i] = blockHash[i];

	hash1[8].y = mod1;
	hash1[9].x = mod2;
	blake2b_compress2(first, blakeInit, hash1, 76);

	for (int i = 0; i<4; i++)
		blockhash_byte[i + 128 * offset] = first[i];


	for (int j = 0; j < 29; j++) {

		blake2b_compress3(blakeInit, first, 64);

		for (int i = 0; i<4; i++)
			blockhash_byte[128 * offset + (i + 4 * (j + 1))] = first[i];
	}
	blake2b_compress3(blakeInit, first, 64);
	for (int i = 0; i<8; i++)
		blockhash_byte[128 * offset + (i + 4 * (29 + 1))] = first[i];

}



__device__ static void fill_block4_doubleshared_mtp_output_bhdr(uint4  * output, const uint4  * __restrict__ block /*, uint32_t *blockHistory*/, 
uint32_t prev_block_offset, uint32_t ref_block_offset)
{
		uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
		uint32 pDat[4]={0};
	__shared__ uint2 blockR[128];
	__shared__ uint2 block_tmp[128];
	uint32_t shift2 = 128 * (threadIdx.x / 32);
	uint32_t shift = 64 * (threadIdx.x / 32);
	uint32_t itu4 = 64 / 32; //(gpu_shared/8);
	uint32_t itu2 = 128 / 32; //(gpu_shared/8);
							  //	if (threadIdx.x < 32) return;

	for (int i = 0; i<itu4; i++)
		((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = block[itu4 * (threadIdx.x % 32) + i + 64 * ref_block_offset];

	for (int i = 0; i<itu4; i++)
		((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] ^= block[itu4 * (threadIdx.x % 32) + i + 64 * prev_block_offset];

	for (int i = 0; i<itu4; i++)
		((uint4*)block_tmp)[shift + itu4 * (threadIdx.x % 32) + i] = ((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i];

	__syncthreads();

 
	for (int i = 0; i<itu4; i++)
	if ((shift + itu4 * (threadIdx.x % 32) + i)==8)
		((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = ((uint4*)pData)[0];
//if (thread==0)
//		printf("GPU pdat %08x %08x %08x %08x\n",pData[0],pData[1],pData[2],pData[3]);

//
	__syncthreads();

#define G(a,b,c,d) \
   { \
     a = fBlaMka(a,b); \
     d = eorswap32(d ,a); \
     c = fBlaMka(c,d); \
     b = ROR2(b ^ c, 24); \
     a = fBlaMka(a,b); \
     d = ROR16(d ^ a); \
     c = fBlaMka(c,d); \
     b = ROR2(b ^ c, 63); \
  } 

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)  \
  { \
    G(v0,v4,v8,v12); \
    G(v1,v5,v9,v13); \
    G(v2,v6,v10,v14); \
    G(v3,v7,v11,v15); \
    G(v0,v5,v10,v15); \
    G(v1,v6,v11,v12); \
    G(v2,v7,v8,v13); \
    G(v3,v4,v9,v14); \
  }

	/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
	(16,17,..31)... finally (112,113,...127) */
	if ((threadIdx.x % 32) <8) {

		//		for (int i = 0; i < 8; i++) {
		{
			int i = threadIdx.x % 32;
			BLAKE2_ROUND_NOMSG(
				blockR[shift2 + 16 * i], blockR[shift2 + 16 * i + 1], blockR[shift2 + 16 * i + 2],
				blockR[shift2 + 16 * i + 3], blockR[shift2 + 16 * i + 4], blockR[shift2 + 16 * i + 5],
				blockR[shift2 + 16 * i + 6], blockR[shift2 + 16 * i + 7], blockR[shift2 + 16 * i + 8],
				blockR[shift2 + 16 * i + 9], blockR[shift2 + 16 * i + 10], blockR[shift2 + 16 * i + 11],
				blockR[shift2 + 16 * i + 12], blockR[shift2 + 16 * i + 13], blockR[shift2 + 16 * i + 14],
				blockR[shift2 + 16 * i + 15]);
		}

		/* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
		(2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */


		__syncthreads();
		{
			//	for (int i = 0; i < 8; i++) {
			int i = threadIdx.x % 32;
			BLAKE2_ROUND_NOMSG(
				blockR[shift2 + 2 * i], blockR[shift2 + 2 * i + 1], blockR[shift2 + 2 * i + 16],
				blockR[shift2 + 2 * i + 17], blockR[shift2 + 2 * i + 32], blockR[shift2 + 2 * i + 33],
				blockR[shift2 + 2 * i + 48], blockR[shift2 + 2 * i + 49], blockR[shift2 + 2 * i + 64],
				blockR[shift2 + 2 * i + 65], blockR[shift2 + 2 * i + 80], blockR[shift2 + 2 * i + 81],
				blockR[shift2 + 2 * i + 96], blockR[shift2 + 2 * i + 97], blockR[shift2 + 2 * i + 112],
				blockR[shift2 + 2 * i + 113]);
		}
	}

	__syncthreads();
	for (int i = 0; i<itu2; i++)
		block_tmp[shift2 + itu2 * (threadIdx.x % 32) + i] ^= blockR[shift2 + itu2 * (threadIdx.x % 32) + i];



	for (int i = 0; i<itu4; i++)
		output[itu4 * (threadIdx.x % 32) + i] = ((uint4*)block_tmp)[shift + itu4 * (threadIdx.x % 32) + i];

	__syncthreads();
#undef G 
#undef BLAKE2_ROUND_NOMSG
}

__device__ static void fill_block4_doubleshared_mtp_output_bhdr_idx(uint4  * output, const uint4  * __restrict__ block /*, uint32_t *blockHistory*/,
	uint32_t prev_block_offset, uint32_t ref_block_offset)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint32 pDat[4] = { 0 };
	__shared__ uint2 blockR[128];
	__shared__ uint2 block_tmp[128];
//	uint4 IndexContainer = {ref_block_offset,0,0,0};
	uint4 IndexContainer = {0,0,ref_block_offset,0};

	uint32_t shift2 = 128 * (threadIdx.x / 32);
	uint32_t shift = 64 * (threadIdx.x / 32);
	uint32_t itu4 = 64 / 32; //(gpu_shared/8);
	uint32_t itu2 = 128 / 32; //(gpu_shared/8);
							  //	if (threadIdx.x < 32) return;

	for (int i = 0; i<itu4; i++)
		((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = block[itu4 * (threadIdx.x % 32) + i + 64 * ref_block_offset];

	for (int i = 0; i<itu4; i++)
		((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] ^= block[itu4 * (threadIdx.x % 32) + i + 64 * prev_block_offset];

	for (int i = 0; i<itu4; i++)
		((uint4*)block_tmp)[shift + itu4 * (threadIdx.x % 32) + i] = ((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i];

	__syncthreads();


	for (int i = 0; i<itu4; i++) {
		if ((shift + itu4 * (threadIdx.x % 32) + i) == 7)
			((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = IndexContainer;
		if ((shift + itu4 * (threadIdx.x % 32) + i) == 8)
			((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = ((uint4*)pData)[0];
		if ((shift + itu4 * (threadIdx.x % 32) + i) == 9)
			((uint4*)blockR)[shift + itu4 * (threadIdx.x % 32) + i] = ((uint4*)pData)[1];
	}
	//if (thread==0)
	//		printf("GPU pdat %08x %08x %08x %08x\n",pData[0],pData[1],pData[2],pData[3]);

	//
	__syncthreads();

#define G(a,b,c,d) \
   { \
     a = fBlaMka(a,b); \
     d = eorswap32(d ,a); \
     c = fBlaMka(c,d); \
     b = ROR2(b ^ c, 24); \
     a = fBlaMka(a,b); \
     d = ROR16(d ^ a); \
     c = fBlaMka(c,d); \
     b = ROR2(b ^ c, 63); \
  } 

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)  \
  { \
    G(v0,v4,v8,v12); \
    G(v1,v5,v9,v13); \
    G(v2,v6,v10,v14); \
    G(v3,v7,v11,v15); \
    G(v0,v5,v10,v15); \
    G(v1,v6,v11,v12); \
    G(v2,v7,v8,v13); \
    G(v3,v4,v9,v14); \
  }

	/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
	(16,17,..31)... finally (112,113,...127) */
	if ((threadIdx.x % 32) <8) {

		//		for (int i = 0; i < 8; i++) {
		{
			int i = threadIdx.x % 32;
			BLAKE2_ROUND_NOMSG(
				blockR[shift2 + 16 * i], blockR[shift2 + 16 * i + 1], blockR[shift2 + 16 * i + 2],
				blockR[shift2 + 16 * i + 3], blockR[shift2 + 16 * i + 4], blockR[shift2 + 16 * i + 5],
				blockR[shift2 + 16 * i + 6], blockR[shift2 + 16 * i + 7], blockR[shift2 + 16 * i + 8],
				blockR[shift2 + 16 * i + 9], blockR[shift2 + 16 * i + 10], blockR[shift2 + 16 * i + 11],
				blockR[shift2 + 16 * i + 12], blockR[shift2 + 16 * i + 13], blockR[shift2 + 16 * i + 14],
				blockR[shift2 + 16 * i + 15]);
		}

		/* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
		(2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */


		__syncthreads();
		{
			//	for (int i = 0; i < 8; i++) {
			int i = threadIdx.x % 32;
			BLAKE2_ROUND_NOMSG(
				blockR[shift2 + 2 * i], blockR[shift2 + 2 * i + 1], blockR[shift2 + 2 * i + 16],
				blockR[shift2 + 2 * i + 17], blockR[shift2 + 2 * i + 32], blockR[shift2 + 2 * i + 33],
				blockR[shift2 + 2 * i + 48], blockR[shift2 + 2 * i + 49], blockR[shift2 + 2 * i + 64],
				blockR[shift2 + 2 * i + 65], blockR[shift2 + 2 * i + 80], blockR[shift2 + 2 * i + 81],
				blockR[shift2 + 2 * i + 96], blockR[shift2 + 2 * i + 97], blockR[shift2 + 2 * i + 112],
				blockR[shift2 + 2 * i + 113]);
		}
	}

	__syncthreads();
	for (int i = 0; i<itu2; i++)
		block_tmp[shift2 + itu2 * (threadIdx.x % 32) + i] ^= blockR[shift2 + itu2 * (threadIdx.x % 32) + i];



	for (int i = 0; i<itu4; i++)
		output[itu4 * (threadIdx.x % 32) + i] = ((uint4*)block_tmp)[shift + itu4 * (threadIdx.x % 32) + i];

	__syncthreads();
#undef G 
#undef BLAKE2_ROUND_NOMSG
}



__global__
void mtp_yloop(uint32_t threads, uint32_t startNounce, const uint4  * __restrict__ DBlock, const uint2  * __restrict__ DBlockHistory,
 const uint4 * __restrict__ MerkleRootElements, uint32_t * __restrict__ SmallestNonce, uint32_t* result)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint32_t NonceNumber = 1;  // old
	uint32_t ThreadNumber = 32;
	uint32_t event_thread = thread / ThreadNumber;
	uint32_t NonceIterator = startNounce + event_thread;
	//	uint32_t thread_event = thread / event_base; // might be a lot (considering this isn't thread per blocks)
	if (event_thread < threads)
	{



		// pointers
		const uint2 *    __restrict__ BlockHistory = &DBlockHistory[0];
		const uint4 *	 __restrict__ GBlock	   = &DBlock[0];

//if (thread==0)
//	printf("coming here blockhistory %08x %08x \n",BlockHistory[10].x,BlockHistory[10].y);

		__shared__ uint8 YLocal;
			
		if (threadIdx.x%32 == 0) {
		uint16 DataChunk[2] = { 0 };
/*
		DataChunk[0].lo = swapvec(((uint8*)Elements)[0]);
		DataChunk[0].hi.s0 = (cuda_swab32(NonceIterator));  // uint32_t nonce implementation nonce
		DataChunk[0].hi.s1 = 0x80000000;
		DataChunk[0].sf = 288; // 264; uint8_t nonce
		YLocal = swapvec(sha256_Transform2(DataChunk, H256));

*/

		DataChunk[0].lo = ((uint8*)Elements)[0];
		DataChunk[0].hi.s0 = NonceIterator;
//		DataChunk[0].hi.s1 = 0x80000000;
//		DataChunk[0].sf = 288; // 264; uint8_t nonce
		//printf("NonceIterator=%08x event_thread=%08x startNonce=%08x\n",NonceIterator,event_thread,startNounce);
//		YLocal = swapvec(sha256_Transform2(DataChunk, H256));
		blake2b_compress2_256((uint2*)&YLocal,blakeFinal,(uint2*)DataChunk,36);

		}
		__syncthreads();

		__shared__ bool init_blocks; 
		__shared__ uint32_t unmatch_block;
		__shared__ uint32_t localIndex;
		init_blocks = false;
		unmatch_block = 0;

		__shared__ uint32_t TestY;
		for (int j = 1; j <= mtp_L; j++)
		{
			if (threadIdx.x%32==0) {
				localIndex = YLocal.s0%(argon_memcost);
			if (j==1) TestY=YLocal.s0;
				if (localIndex == 0 || localIndex == 1) {
					init_blocks = true;
					break;
				}

			}
			__syncthreads();
			__shared__ uint4 X_IJ[64];

			uint2 history = BlockHistory[localIndex];

			uint32_t ref_block  = history.y;
			uint32_t prev_block = history.x;
			fill_block4_doubleshared_mtp_output_bhdr_idx(X_IJ, GBlock, prev_block, ref_block);

			int countIndex;
			for (countIndex = threadIdx.x%32; countIndex < 128; countIndex+=32) {
				if (((uint64_t*)X_IJ)[countIndex] != ((uint64_t*)GBlock)[localIndex * 128 + countIndex]) {
				atomicAdd(&unmatch_block,1);
					break;
				}
			}
			__syncthreads();
			if (unmatch_block>0) break;
			
			if (threadIdx.x%32==0) {

				uint16 DataChunk[2];
				DataChunk[0].lo = YLocal;
				DataChunk[0].hi = ((uint8*)GBlock)[localIndex * 32];
				DataChunk[1].lo = ((uint8*)GBlock)[localIndex * 32 + 1];
				DataChunk[1].hi = ((uint8*)GBlock)[localIndex * 32 + 2];
				uint32_t len = 128;
				uint16 DataTmp = {0}; // = sha256_Transform2(DataChunk, H256);
				blake2b_compress2b((uint2*)&DataTmp, blakeFinal, (uint2*)DataChunk, len);
//				if (NonceIterator == startNounce && j == 1)
//					printf("datatmp 1 %08x %08x %08x %08x  %08x %08x %08x %08x  %08x %08x %08x %08x  %08x %08x %08x %08x \n"
//					, DataTmp.s0, DataTmp.s1, DataTmp.s2, DataTmp.s3, DataTmp.s4, DataTmp.s5, DataTmp.s6, DataTmp.s7, 
//						DataTmp.s8, DataTmp.s9, DataTmp.sa, DataTmp.sb, DataTmp.sc, DataTmp.sd, DataTmp.se, DataTmp.sf);

				for (int i = 0; i < 7; i++) {
					len += (i&1==0)? 32:128;
					DataChunk[0].lo = ((uint8*)GBlock)[localIndex * 32 + 3 + 4 * i + 0];
					DataChunk[0].hi = ((uint8*)GBlock)[localIndex * 32 + 3 + 4 * i + 1];
					DataChunk[1].lo = ((uint8*)GBlock)[localIndex * 32 + 3 + 4 * i + 2];
					DataChunk[1].hi = ((uint8*)GBlock)[localIndex * 32 + 3 + 4 * i + 3];
//					DataTmp = sha256_Transform2(DataChunk, DataTmp);
					uint16 DataTmp2;
					blake2b_compress2b((uint2*)&DataTmp2, (uint2*)&DataTmp, (uint2*)DataChunk, len);
					DataTmp = DataTmp2;
//					if (NonceIterator == startNounce && j == 1)
//						printf("len %08x datatmp %d %08x %08x %08x %08x  %08x %08x %08x %08x \n",len,i+1, DataTmp.s0, DataTmp.s1, DataTmp.s2, DataTmp.s3, DataTmp.s4, DataTmp.s5, DataTmp.s6, DataTmp.s7);

				}
				DataChunk[0].lo = ((uint8*)GBlock)[localIndex * 32 + 31];
				DataChunk[0].hi = {0};
				DataChunk[1].lo = { 0 };
				DataChunk[1].hi = { 0 };
//				DataChunk[0].sf = (1024 + 32) * 8;
//				YLocal = swapvec(sha256_Transform2(DataChunk, DataTmp));
				blake2b_compress2c_256((uint2*)&YLocal, (uint2*)&DataTmp, (uint2*)DataChunk, 1024+32);

			}
			__syncthreads();
		}
		// end loop		

		if (init_blocks) {
			return; // not a solution
		}


		if (unmatch_block>0) {
			return; // not a solution
		}
		// search if there are d trailing 0


//		if (((uint64_t*)state)[3] <= ((uint64_t*)pTarget)[3]) {
		if (threadIdx.x % 32 == 0 && (YLocal.s7 <= pTarget[7])) 
//		if (threadIdx.x % 32 == 0 && NonceIterator == startNounce)
		{
		atomicMin(&SmallestNonce[0],NonceIterator);
		}
		__syncthreads();

		if (threadIdx.x%32==0 &&  (YLocal.s7 <= pTarget[7]) && NonceIterator==SmallestNonce[0]) {
//		if (threadIdx.x % 32 == 0 && NonceIterator == startNounce && NonceIterator == SmallestNonce[0]) {
			((uint8*)result)[0] = YLocal;
			printf("TestY = %08x\n",TestY);
			printf("Nonce = %08x\n", SmallestNonce[0]);
			printf("thread = %d GPU YLocal final %08x %08x %08x %08x %08x %08x %08x %08x \n",thread/32,YLocal.s0, YLocal.s1, YLocal.s2, YLocal.s3, 
				YLocal.s4, YLocal.s5, YLocal.s6, YLocal.s7);
		


		
		}

	}
}



__host__
void mtp_cpu_init(int thr_id, uint32_t threads)
{

	// just assign the device pointer allocated in main loop

printf("number of threads %d \n",threads);
	cudaMalloc((void**)&HBlock, 256 * argon_memcost * sizeof(uint32_t) );
	cudaMalloc((void**)&HBlockHistory, argon_memcost * sizeof(uint64_t) );

	cudaMalloc(&d_GNonces[thr_id], 8 * sizeof(uint32_t));
	cudaMallocHost(&h_GNonces[thr_id], 8 * sizeof(uint32_t));
	cudaMalloc(&d_MinNonces[thr_id], sizeof(uint32_t));
	cudaMallocHost(&h_MinNonces[thr_id],  sizeof(uint32_t));
}


__host__
void mtp_setBlockTarget(const void* pDataIn,const void *pTargetIn, const void * zElement)
{

	printf("the target %08x %08x %08x %08X  %08x %08x %08x %08X \n",
		((uint32_t*)pTargetIn)[0],
		((uint32_t*)pTargetIn)[1],
		((uint32_t*)pTargetIn)[2],
		((uint32_t*)pTargetIn)[3],
		((uint32_t*)pTargetIn)[4],
		((uint32_t*)pTargetIn)[5],
		((uint32_t*)pTargetIn)[6],
		((uint32_t*)pTargetIn)[7]
);
	cudaMemcpyToSymbol(pData, pDataIn, 32, 0, cudaMemcpyHostToDevice); // shortened message
	cudaMemcpyToSymbol(pTarget, pTargetIn, 32, 0, cudaMemcpyHostToDevice);	
	cudaMemcpyToSymbol(Elements, zElement, 8*sizeof(uint32_t), 0, cudaMemcpyHostToDevice);

}

__host__
void mtp_fill(const uint64_t *Block, const uint64_t zblockHistory,uint32_t offset)
{
//uint4 TransBlock[64];
//	memcpy(TransBlock,Block,256*sizeof(uint32_t*));
//	cudaMemcpyToSymbol(HBlock, Block, sizeof(Block), offset*sizeof(Block), cudaMemcpyHostToDevice);
uint4 *Blockptr   = &HBlock[offset*64];
uint2 *Historyptr = &HBlockHistory[offset];
	cudaMemcpyAsync(Blockptr, Block, 256 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	cudaMemcpyAsync(Historyptr, &zblockHistory, 2 * sizeof(uint32_t), cudaMemcpyHostToDevice);
}

__host__
uint32_t mtp_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash)
{

	uint32_t result = UINT32_MAX;
	cudaMemset(d_GNonces[thr_id], 0xff, 8 * sizeof(uint32_t));
	cudaMemset(d_MinNonces[thr_id],0xff,sizeof(uint32_t));
	int dev_id = device_map[thr_id % MAX_GPUS];

	uint32_t tpb = 32; //TPB52;
 
	dim3 gridyloop(threads*32/tpb);
	dim3 blockyloop(tpb);

	mtp_yloop << < gridyloop,blockyloop >> >(threads,startNounce,HBlock,HBlockHistory,Elements,d_MinNonces[thr_id],d_GNonces[thr_id]);

	
	// get first found nonce
	cudaMemcpy(h_GNonces[thr_id], d_GNonces[thr_id], 8 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
	cudaMemcpy(h_MinNonces[thr_id], d_MinNonces[thr_id], sizeof(uint32_t), cudaMemcpyDeviceToHost);
if (h_MinNonces[thr_id][0]!=0xffffffff)
printf("Nonce %08x sol one %08x %08x %08x %08x %08x %08x %08x %08x\n",h_MinNonces[thr_id][0], h_GNonces[thr_id][0], 
	  h_GNonces[thr_id][1], h_GNonces[thr_id][2], h_GNonces[thr_id][3], h_GNonces[thr_id][4], h_GNonces[thr_id][5], 
	  h_GNonces[thr_id][6], h_GNonces[thr_id][7]);
else 
printf("startNounce=%08x threads=%08x sum=%08x\n",startNounce,threads,startNounce+threads);
	result = *h_MinNonces[thr_id];
	return result;

}
