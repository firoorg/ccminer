/**
* MTP
* djm34 2017-2018
* krnlx 2018
**/

#include <stdio.h>
#include <memory.h>
#define TPB_MTP75 128
#if __CUDA_ARCH__ >= 750
#define TPB_MTP 128
#define REG 2
#else
#define TPB_MTP 320
#define REG 1
#endif
#define Granularity 8
#define Granularity2 8
#define Type uint4
#define BlakeType uint2
#define Zeroing  make_uint4(0,0,0,0)
#define Gran3  Granularity * 3 / 4
#define Gran1  Granularity * 1 / 4
#define SHR_OFF REG
#define FARLOAD(x) far[warp][(x)*(Granularity+SHR_OFF) + lane]
#define FARSTORE(x) far[warp][lane*(Granularity+SHR_OFF) + (x)]



#include "lyra2/cuda_lyra2_vectors.h"
static uint32_t *h_MinNonces[16]; // this need to get fixed as the rest of that routine
static uint32_t *d_MinNonces[16];

__constant__ uint32_t pTarget[8];
__constant__ uint32_t pData[20]; // truncated data
__constant__ uint4 Elements[1];

/*__constant__*/ uint4 * HBlock[16];
//uint8 * GYLocal[16];
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
	else if (offset == 32) {
		result.x = tmp.y;
		result.y = tmp.x;
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

__device__ __forceinline__
uint2 ROTR64X(const uint2 tmp, const int offset) {
	uint2 result;

	if (offset < 32) { //wrong
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
	}
	else {
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
	}
	return result;
}
__device__ __forceinline__
uint2 ROTR64X8(const uint2 tmp) {
	uint2 result;
	result.x = __byte_perm(tmp.x, tmp.y, 0x4321);
	result.y = __byte_perm(tmp.y, tmp.x, 0x4321);
	return result;
}

__device__ __forceinline__
uint2 ROTR64X16(const uint2 tmp) {
	uint2 result;
	result.x = __byte_perm(tmp.x, tmp.y, 0x5432);
	result.y = __byte_perm(tmp.y, tmp.x, 0x5432);
	return result;
}

__device__ __forceinline__
uint2 ROTR64X24(const uint2 tmp) {
	uint2 result;
	result.x = __byte_perm(tmp.x, tmp.y, 0x6543);
	result.y = __byte_perm(tmp.y, tmp.x, 0x6543);
	return result;
}

__device__ __forceinline__
uint2 ROTR64XB32(const uint2 tmp, const int offset) {
	uint2 result;
	asm volatile ("shf.l.clamp.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
	asm volatile ("shf.l.clamp.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.x), "r"(tmp.y), "r"(offset));

	return result;
}



__device__ __forceinline__
uint2 ROTR64XS32(const uint2 tmp, const int offset) {
	uint2 result; // probably wrong
	asm volatile ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
	asm volatile ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
	return result;
}
__constant__ static const uint32_t blake2b_sigma[12][16] =
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


#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] +  (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap32(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X24(v[b] ^ v[c]); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X16(v[d] ^ v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64XB32(v[b] ^ v[c], 1); \
  } 

#define Gu(r,i,a,b,c,d) \
   { \
     v.ll[a] +=   v.ll[b] +  (m.ll[blake2b_sigma[r][2*i]]); \
     v.u2[d] = eorswap32(v.u2[d] , v.u2[a]); \
     v.ll[c] += v.ll[d]; \
     v.u2[b] = ROTR64X24(v.u2[b] ^ v.u2[c]); \
     v.ll[a] += v.ll[b] + (m.ll[blake2b_sigma[r][2*i+1]]); \
     v.u2[d] = ROTR64X16(v.u2[d] ^ v.u2[a]); \
     v.ll[c] += v.ll[d]; \
     v.u2[b] = ROTR64XB32(v.u2[b] ^ v.u2[c], 1); \
  } 
/*
#define Gu(r,i,a,b,c,d) \
   { \
     v.u2[a] +=   v.u2[b] +  (m.u2[blake2b_sigma[r][2*i]]); \
     v.u2[d] = eorswap32(v.u2[d] , v.u2[a]); \
     v.u2[c] += v.u2[d]; \
     v.u2[b] = ROTR64X24(v.u2[b] ^ v.u2[c]); \
     v.u2[a] += v.u2[b] + (m.u2[blake2b_sigma[r][2*i+1]]); \
     v.u2[d] = ROTR64X16(v.u2[d] ^ v.u2[a]); \
     v.u2[c] += v.u2[d]; \
     v.u2[b] = ROTR64XB32(v.u2[b] ^ v.u2[c], 1); \
  } 
*/

#define ROUNDu(r)  \
  { \
    Gu(r,0, 0,4,8,12); \
    Gu(r,1, 1,5,9,13); \
    Gu(r,2, 2,6,10,14); \
    Gu(r,3, 3,7,11,15); \
    Gu(r,4, 0,5,10,15); \
    Gu(r,5, 1,6,11,12); \
    Gu(r,6, 2,7,8,13); \
    Gu(r,7, 3,4,9,14); \
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

/*
static __device__ __forceinline__ uint2 swap32(uint2 u, uint2 v) {

	return make_uint2(u.y, u.x);
}
*/

static __device__ __forceinline__ uint2 eorswap32(uint2 u, uint2 v) {
	u ^= v; 
	return make_uint2(u.y,u.x);
}

/*
static __device__ __forceinline__ uint64_t eorswap64(uint64_t u, uint64_t v) {
	return ROTR64X(u^v, 32);
}
*/

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
	asm volatile ("mov.u32 %0, %tid.x;" : "=r"(ret));
	return ret;
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


__device__ __forceinline__ uint4 __ldca2(const uint4 * __restrict__ ptr, uint4 ret) { 
 asm volatile ("{prefetchu.L1 [%4]; ld.global.cs.v4.u32 {%0,%1,%2,%3}, [%4];}"  : "=r"(ret.x), "=r"(ret.y), "=r"(ret.z), "=r"(ret.w) : __LDG_PTR(ptr)); 
return ret; 
}

__device__ __forceinline__ uint8 __ldcg2(const uint8 * __restrict__ ptr) {
	uint8 ret;
	asm volatile ("{prefetchu.L1 [%4]; ld.global.cg.v4.u32 {%0,%1,%2,%3}, [%4];}"  : "=r"(ret.s0), "=r"(ret.s1), "=r"(ret.s2), "=r"(ret.s3) : __LDG_PTR(ptr));
	asm volatile ("{prefetchu.L1 [%4+16]; ld.global.cg.v4.u32 {%0,%1,%2,%3}, [%4+16];}"  : "=r"(ret.s4), "=r"(ret.s5), "=r"(ret.s6), "=r"(ret.s7) : __LDG_PTR(ptr));
	return ret;
}

__device__ __forceinline__ ulonglong2 __ldcg2(const ulonglong2 * __restrict__ ptr) {
	ulonglong2 ret;
	asm volatile ("ld.global.cg.v2.u64 {%0,%1}, [%2];"  : "=l"(ret.x), "=l"(ret.y) : __LDG_PTR(ptr)); 
	return ret;
}

//__device__ __forceinline__ uint4 __ldlu(const uint4 * __restrict__ ptr) { uint4 ret; asm volatile ("ld.global.lu.v4.u32 {%0,%1,%2,%3}, [%4];"  : "=r"(ret.x), "=r"(ret.y), "=r"(ret.z), "=r"(ret.w) : __LDG_PTR(ptr)); return ret; }

__device__ __forceinline__ void blakeL1(uint2 &a,uint2 b, uint64_t m) 
{
	asm("{ // uint2 a+=b+c \n\t"
		".reg .b64 r1,r2; \n\t"
		"mov.b64 r1,{%0,%1}; \n\t"
		"mov.b64 r2,{%2,%3}; \n\t"
		"add.u64 r1,r1,r2; \n\t"
		"add.u64 r1,r1,%4; \n\t"
		"mov.b64 {%0,%1},r1; \n\n"
		"}\n" : "+r"(a.x), "+r"(a.y) :  "r"(b.x), "r"(b.y),"l"(m));
}



typedef union {
	uint8      u8[4];
	uint4      u4[8];
	ulonglong2 l2[8];
	uint2      u2[16];
	uint64_t   ll[16];
} united;

__device__ __forceinline__ uint4 __shfl4(unsigned  mask, uint4 Tmp, int lane)
{
return make_uint4(
__shfl_sync(mask, Tmp.x, lane, Granularity2),
__shfl_sync(mask, Tmp.y, lane, Granularity2),
__shfl_sync(mask, Tmp.z, lane, Granularity2),
__shfl_sync(mask, Tmp.w, lane, Granularity2));
}

__device__ __forceinline__ ulonglong2 __shfll2(unsigned  mask, ulonglong2 Tmp, int lane)
{
	ulonglong2 Tmp2;
	Tmp2.x = __shfl_sync(mask, Tmp.x, lane, Granularity2);
	Tmp2.y = __shfl_sync(mask, Tmp.y, lane, Granularity2);
	return Tmp2;
}

__device__ __forceinline__ uint32_t switcher (uint32_t Val0, uint32_t Val1, uint32_t Val2, uint32_t Val3, uint32_t Val4, uint32_t Val5, uint32_t Val6, uint32_t Val7, uint32_t lane)
{
	switch (lane)
	{
	case 0:
		return Val0;
	case 1:
		return Val1;
	case 2:
		return Val2;
	case 3:
		return Val3;
	case 4:
		return Val4;
	case 5:
		return Val5;
	case 6:
		return Val6;
	case 7:
		return Val7;
	}
return 0;
}

__device__ __forceinline__ void direct(uint32_t NewVal,uint32_t &Val0, uint32_t &Val1, uint32_t &Val2, uint32_t &Val3, uint32_t &Val4, uint32_t &Val5, uint32_t &Val6, uint32_t &Val7, uint32_t lane)
{
	switch (lane)
	{
	case 0:
		Val0 = NewVal;
		return;
	case 1:
		Val1 = NewVal;
		return;
	case 2:
		Val2 = NewVal;
		return;
	case 3:
		Val3 = NewVal;
		return;
	case 4:
		Val4 = NewVal;
		return;
	case 5:
		Val5 = NewVal;
		return;
	case 6:
		Val6 = NewVal;
		return;
	case 7:
		Val7 = NewVal;
		return;
	}
}

__device__ __forceinline__ uint4 switcher(uint4 Val0, uint4 Val1, uint4 Val2, uint4 Val3, uint4 Val4, uint4 Val5, uint4 Val6, uint4 Val7, uint32_t lane)
{

		return (lane==0)? Val0 : (lane == 1) ? Val1 : (lane == 2) ? Val2 : (lane == 3) ? Val3 : (lane == 4) ? Val4 : (lane == 5) ? Val5 : (lane == 6) ? Val6 :  Val7; 

		

}

__device__ __forceinline__ void switcher2(Type &NewVal, Type Val0, Type Val1, Type Val2, Type Val3, Type Val4, Type Val5, Type Val6, Type Val7, int lane)
{

//	return (lane == 0) ? Val0 : (lane == 1) ? Val1 : (lane == 2) ? Val2 : (lane == 3) ? Val3 : (lane == 4) ? Val4 : (lane == 5) ? Val5 : (lane == 6) ? Val6 : Val7;
		NewVal = (lane == 0) ? Val0 : NewVal;
		NewVal = (lane == 1) ? Val1 : NewVal;
		NewVal = (lane == 2) ? Val2 : NewVal;
		NewVal = (lane == 3) ? Val3 : NewVal;
		NewVal = (lane == 4) ? Val4 : NewVal;
		NewVal = (lane == 5) ? Val5 : NewVal;
		NewVal = (lane == 6) ? Val6 : NewVal;
		NewVal = (lane == 7) ? Val7 : NewVal;

}

__device__ __forceinline__ void switcher3(Type &NewVal, Type *Val, int lane)
{

	//	return (lane == 0) ? Val0 : (lane == 1) ? Val1 : (lane == 2) ? Val2 : (lane == 3) ? Val3 : (lane == 4) ? Val4 : (lane == 5) ? Val5 : (lane == 6) ? Val6 : Val7;
#pragma unroll
for (int t=0;t<8;t++)
	NewVal = (lane == t) ? Val[t] : NewVal;


}

__device__ __forceinline__ void direct(Type NewVal, Type &Val0, Type &Val1, Type &Val2, Type &Val3, Type &Val4, Type &Val5, Type &Val6, Type &Val7, int lane)
{


	Val0 = (lane == 0) ? NewVal : Val0;
	Val1 = (lane == 1) ? NewVal : Val1;
	Val2 = (lane == 2) ? NewVal : Val2;
	Val3 = (lane == 3) ? NewVal : Val3;
	Val4 = (lane == 4) ? NewVal : Val4;
	Val5 = (lane == 5) ? NewVal : Val5;
	Val6 = (lane == 6) ? NewVal : Val6;
	Val7 = (lane == 7) ? NewVal : Val7;


}



__global__ __launch_bounds__(TPB_MTP, 2)
void yloop_init(uint32_t thr_id, uint32_t threads, uint32_t startNounce, uint8 *GY)
{
	unsigned mask = __activemask();
	//	mask = 0xffffffff;
	//	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);


	uint32_t event_thread = (blockDim.x * blockIdx.x + threadIdx.x); //thread / ThreadNumber;
	uint32_t NonceIterator = startNounce + event_thread;

		uint2 YLocal[4];


		const uint2 blakeIVl[8] =
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

		const uint2 blakeFinall[8] =
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


		united  v;
		united m = { 0 };
		uint4 *TheDat = &((uint4*)pData)[0];
		for (int i = 0; i<5; i++)
		{
			asm volatile("prefetchu.L1 [%0];" : : "l"(&TheDat[i]));
			m.u4[i] = __ldca(&TheDat[i]);
		}
		asm volatile("prefetchu.L1 [%0];" : : "l"(&Elements[0]));
		m.u4[5] = __ldca(&Elements[0]);
		m.u4[6].x = NonceIterator;

		//////////////////////////////
#pragma unroll
		for (int i = 0; i < 8; ++i)
			v.u2[i] = blakeFinall[i];


		v.u2[8] = blakeIVl[0];
		v.u2[9] = blakeIVl[1];
		v.u2[10] = blakeIVl[2];
		v.u2[11] = blakeIVl[3];
		v.u2[12] = blakeIVl[4];
		v.u2[12].x ^= 100;
		v.u2[13] = blakeIVl[5];
		v.u2[14] = ~blakeIVl[6];
		v.u2[15] = blakeIVl[7];


#pragma unroll 
		for (int i = 0; i<12; i++)
			ROUNDu(i);

#pragma unroll
		for (int i = 0; i < 4; ++i)
			((BlakeType*)&YLocal)[i] = blakeFinall[i] ^ v.u2[i] ^ v.u2[i + 8];


		GY[event_thread] = ((uint8*)YLocal)[0];
}


__global__   /*__launch_bounds__(TPB_MTP, 2)*/  
void mtp_yloop_old(uint32_t thr_id, uint32_t threads, uint32_t startNounce, const Type  * __restrict__ GBlock,
	uint32_t * __restrict__ SmallestNonce)
{

	unsigned mask = /* 0xFFFFFFFF; */ __activemask();
	uint32_t event_thread = (blockDim.x * blockIdx.x + threadIdx.x); //thread / ThreadNumber;
	uint32_t NonceIterator = startNounce + event_thread;
	int lane = lane_id() % (Granularity2);
	int warp = threadIdx.x / (Granularity2);


	{

		uint2 YLocal[4];
		

		const uint2 blakeIVl[8] =
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

		const uint2 blakeFinall[8] =
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


		united  v;
		united m = { 0 };




		uint4 *TheDat = &((uint4*)pData)[0];
		for (int i = 0; i<5; i++)
		{
			asm volatile("prefetchu.L1 [%0];" : : "l"(&TheDat[i]));
			m.u4[i] = __ldca(&TheDat[i]);
		}
		asm volatile("prefetchu.L1 [%0];" : : "l"(&Elements[0]));
		m.u4[5] = __ldca(&Elements[0]);
		m.u4[6].x = NonceIterator;

		//////////////////////////////
#pragma unroll
		for (int i = 0; i < 8; ++i)
			v.u2[i] = blakeFinall[i];


		v.u2[8] = blakeIVl[0];
		v.u2[9] = blakeIVl[1];
		v.u2[10] = blakeIVl[2];
		v.u2[11] = blakeIVl[3];
		v.u2[12] = blakeIVl[4];
		v.u2[12].x ^= 100;
		v.u2[13] = blakeIVl[5];
		v.u2[14] = ~blakeIVl[6];
		v.u2[15] = blakeIVl[7];


		#pragma unroll 
		for (int i = 0; i<12; i++)
			ROUNDu(i);

		#pragma unroll
		for (int i = 0; i < 4; ++i)
			((BlakeType*)&YLocal)[i] = blakeFinall[i] ^ v.u2[i] ^ v.u2[i + 8];



		///////////////////////////////
		#pragma unroll 64
		for (int j = 0; j < 64; j++)
		{
			__shared__ __align__(128)  Type far [(TPB_MTP /Granularity2)][Granularity2][Granularity2 + SHR_OFF];

			uint32_t YIndex = (YLocal[0].x & 0x3FFFFF) * (Granularity);

//			YIndex2[warp][lane] = (YLocal[0].x & 0x3FFFFF) * (Granularity);
//			__syncwarp(mask);
			#pragma unroll
			for (int t = 0; t< Gran1; t++)
				m.u4[t] = ((uint4*)YLocal)[t];


			BlakeType DataTmp[8] =
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

			uint32_t len = 0;



			#pragma unroll 8
			for (int i = 0; i < 9; i++) {


				bool last = (i == 8);

				len += last ? 32 : 128;
		
				uint32_t Index = lane  + Granularity * argon_memcost * i; //i * (1 << 25); //// + YIndex;
				int Index2 = lane  + Granularity * i;
			
				#pragma unroll 				
				for (int t = 0; t<Granularity2; t++) {
				uint32_t IndexLocShuff =  Index + __shfl_sync(mask, YIndex ,t, Granularity2) ;
//					uint32_t IndexLocShuff = Index + YIndex2[warp][t];
				asm volatile("prefetchu.L1 [%0];" : : "l"(&GBlock[IndexLocShuff]));
				far[warp][t][lane] = (Index2<64)? __ldca(&GBlock[IndexLocShuff]) :Zeroing;				
				}
				

//				#if __CUDA_ARCH__ == 520
//					__syncwarp(mask);
//				#endif

					#pragma unroll
					for (int t = Gran1; t < Granularity; t++) 
						 m.u4[t] = far[warp][lane][t - Gran1];

				#pragma unroll
				for (int t = 0; t < 8; t++)
					v.u2[t] = DataTmp[t];



				v.u2[8] = blakeIVl[0];
				v.u2[9] = blakeIVl[1];
				v.u2[10] = blakeIVl[2];
				v.u2[11] = blakeIVl[3];
				v.u2[12] = blakeIVl[4];
				v.u2[12].x ^= len;
				v.u2[13] = blakeIVl[5];
				v.u2[14] = last ? ~blakeIVl[6] : blakeIVl[6];
				v.u2[15] = blakeIVl[7];

				#pragma unroll 
				for (int t = 0; t<12; t++)
					ROUNDu(t);

				#pragma unroll 
				for (int t = 0; t < 8; t++)
					DataTmp[t] ^= v.u2[t] ^ v.u2[t + 8];

				if (last) continue;

				#pragma unroll
				for (int t = 0; t< Gran1; t++) 
		   	    m.u4[t] = far[warp][lane][t + Gran3];

			}



			#pragma unroll 
			for (int t = 0; t<4; t++)
				YLocal[t] = DataTmp[t];

		}



		if (((uint64_t*)&YLocal)[3] <= ((uint64_t*)pTarget)[3])
		{
			atomicMin(&SmallestNonce[0], NonceIterator);
		}

	}
 
}



__global__   /*__launch_bounds__(TPB_MTP, 2)*/
void mtp_yloop(uint32_t thr_id, uint32_t threads, uint32_t startNounce, const Type  * __restrict__ GBlock,
	uint32_t * __restrict__ SmallestNonce)
{

	unsigned mask = /* 0xFFFFFFFF; */ __activemask();
	uint32_t event_thread = (blockDim.x * blockIdx.x + threadIdx.x); //thread / ThreadNumber;
	uint32_t NonceIterator = startNounce + event_thread;
	int lane = lane_id() % (Granularity2);
	int warp = threadIdx.x / (Granularity2);


	{

		uint2 YLocal[4];


		const uint2 blakeIVl[8] =
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

		const uint2 blakeFinall[8] =
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


		united  v;
		united m = { 0 };




		uint4 *TheDat = &((uint4*)pData)[0];
		for (int i = 0; i<5; i++)
		{
			asm volatile("prefetchu.L1 [%0];" : : "l"(&TheDat[i]));
			m.u4[i] = __ldca(&TheDat[i]);
		}
		asm volatile("prefetchu.L1 [%0];" : : "l"(&Elements[0]));
		m.u4[5] = __ldca(&Elements[0]);
		m.u4[6].x = NonceIterator;

		//////////////////////////////
#pragma unroll
		for (int i = 0; i < 8; ++i)
			v.u2[i] = blakeFinall[i];


		v.u2[8] = blakeIVl[0];
		v.u2[9] = blakeIVl[1];
		v.u2[10] = blakeIVl[2];
		v.u2[11] = blakeIVl[3];
		v.u2[12] = blakeIVl[4];
		v.u2[12].x ^= 100;
		v.u2[13] = blakeIVl[5];
		v.u2[14] = ~blakeIVl[6];
		v.u2[15] = blakeIVl[7];


#pragma unroll 
		for (int i = 0; i<12; i++)
			ROUNDu(i);

#pragma unroll
		for (int i = 0; i < 4; ++i)
			((BlakeType*)&YLocal)[i] = blakeFinall[i] ^ v.u2[i] ^ v.u2[i + 8];



		///////////////////////////////
#pragma unroll 64
		for (int j = 0; j < 64; j++)
		{
			__shared__ __align__(128)  Type far[(TPB_MTP / Granularity2)][Granularity2][Granularity2 + SHR_OFF];

			uint32_t YIndex = (YLocal[0].x & 0x3FFFFF) * (Granularity);

			//			YIndex2[warp][lane] = (YLocal[0].x & 0x3FFFFF) * (Granularity);
			//			__syncwarp(mask);
#pragma unroll
			for (int t = 0; t< Gran1; t++)
				m.u4[t] = ((uint4*)YLocal)[t];


			BlakeType DataTmp[8] =
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

			uint32_t len = 0;
/*
			uint32_t YIndexLin[Granularity2];
			#pragma unroll 	
			for (int t = 0; t<Granularity2; t++) 
				YIndexLin[t] =  __shfl_sync(mask, YIndex, t, Granularity2);
*/

			#pragma unroll 8
			for (int i = 0; i < 9; i++) {


				bool last = (i == 8);

				len += last ? 32 : 128;

				uint32_t Index = lane + Granularity * argon_memcost * i; //i * (1 << 25); //// + YIndex;
				int Index2 = lane + Granularity * i;

				#pragma unroll 				
				for (int t = 0; t<Granularity2; t++) {
					uint32_t IndexLocShuff = Index + __shfl_sync(mask, YIndex, t, Granularity2);
				//	uint32_t IndexLocShuff = Index + YIndexLin[t];
					//					uint32_t IndexLocShuff = Index + YIndex2[warp][t];
//					asm volatile("prefetchu.L1 [%0];" : : "l"(&GBlock[IndexLocShuff]));
					far[warp][t][lane] = (Index2<64) ? __ldca(&GBlock[IndexLocShuff]) : Zeroing;
				}

				#pragma unroll
				for (int t = Gran1; t < Granularity; t++)
					m.u4[t] = far[warp][lane][t - Gran1];

				#pragma unroll
				for (int t = 0; t < 8; t++)
					v.u2[t] = DataTmp[t];



				v.u2[8] = blakeIVl[0];
				v.u2[9] = blakeIVl[1];
				v.u2[10] = blakeIVl[2];
				v.u2[11] = blakeIVl[3];
				v.u2[12] = blakeIVl[4];
				v.u2[12].x ^= len;
				v.u2[13] = blakeIVl[5];
				v.u2[14] = last ? ~blakeIVl[6] : blakeIVl[6];
				v.u2[15] = blakeIVl[7];

				#pragma unroll 
				for (int t = 0; t<12; t++)
					ROUNDu(t);

				#pragma unroll 
				for (int t = 0; t < 8; t++)
					DataTmp[t] ^= v.u2[t] ^ v.u2[t + 8];

				if (last) continue;

				#pragma unroll
				for (int t = 0; t< Gran1; t++)
					m.u4[t] = far[warp][lane][t + Gran3];

			}


			#pragma unroll 
			for (int t = 0; t<4; t++)
				YLocal[t] = DataTmp[t];

		}



		if (((uint64_t*)&YLocal)[3] <= ((uint64_t*)pTarget)[3])
		{
			atomicMin(&SmallestNonce[0], NonceIterator);
		}

	}

}




__host__
void mtp_cpu_init(int thr_id, uint32_t threads)
{

	cudaSetDevice(device_map[thr_id]);


	cudaMalloc((void**)&HBlock[thr_id], 256 * argon_memcost * sizeof(uint32_t));
	cudaMalloc(&d_MinNonces[thr_id], sizeof(uint32_t));
	cudaMallocHost(&h_MinNonces[thr_id], sizeof(uint32_t));
	cudaMalloc(&Header[thr_id], sizeof(uint32_t) * 8);
	cudaMalloc(&buffer_a[thr_id], 4194304 * 64);

}

__host__
uint32_t get_tpb_mtp(int thr_id)
{
//	cudaSetDevice(device_map[thr_id]);
	uint32_t tpb = (uint32_t)TPB_MTP;
	if (device_sm[device_map[thr_id]] >= 750)
	{ 
		tpb = TPB_MTP75;
	}
 return tpb;
}


__host__
void mtp_setBlockTarget(int thr_id, const void* pDataIn, const void *pTargetIn, const void * zElement, cudaStream_t s0)
{

	CUDA_SAFE_CALL(cudaMemcpyToSymbolAsync(pData, pDataIn, 80, 0, cudaMemcpyHostToDevice, s0));
	CUDA_SAFE_CALL(cudaMemcpyToSymbolAsync(pTarget, pTargetIn, 32, 0, cudaMemcpyHostToDevice, s0));
	CUDA_SAFE_CALL(cudaMemcpyToSymbolAsync(Elements, zElement, 4 * sizeof(uint32_t), 0, cudaMemcpyHostToDevice, s0));

}

__host__
void mtp_fill(uint32_t dev_id, const uint64_t *Block, uint32_t offset, uint32_t datachunk)
{
//	cudaSetDevice(device_map[dev_id]);
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
uint32_t mtp_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce, cudaStream_t s0)
{


//	cudaSetDevice(device_map[thr_id]);
	uint32_t result = UINT32_MAX;
	cudaMemsetAsync(d_MinNonces[thr_id], 0xff, sizeof(uint32_t), s0);

	uint32_t tpb = TPB_MTP; //TPB52;
	if (device_sm[device_map[thr_id]] >= 750)
		tpb = TPB_MTP75;
	
	dim3 gridyloop(threads / tpb);
	dim3 blockyloop(tpb);

	//yloop_init <<<gridyloop, blockyloop>>>(thr_id, threads, startNounce, GYLocal[thr_id]);

	mtp_yloop << < gridyloop, blockyloop,thr_id,s0 >> >(thr_id, threads, startNounce, (Type*)HBlock[thr_id],  d_MinNonces[thr_id]);

	cudaStreamSynchronize(s0);
	cudaMemcpyAsync(h_MinNonces[thr_id], d_MinNonces[thr_id], sizeof(uint32_t), cudaMemcpyDeviceToHost,s0);
	cudaStreamSynchronize(s0);

	result = *h_MinNonces[thr_id];
	return result; 

}




__device__ static int blake2b_compress4x(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len, int last)
{

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
//	uint32_t lanes = 4;

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
	relative_position = _HIDWORD(relative_position * relative_position);

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




__device__ __forceinline__ void copy_block(mem_blk *dst, const mem_blk *src) {
 
	((uint4*)dst->v)[2 * threadIdx.x] = ((uint4*)src->v)[2 * threadIdx.x];
	((uint4*)dst->v)[2 * threadIdx.x + 1] = ((uint4*)src->v)[2 * threadIdx.x + 1];
}

__device__ __forceinline__ void copy_block_sliced(mem_blk *dst, const uint4 *src) {


int MyPlace = (threadIdx.x)/4;
int MyPos   = (threadIdx.x)%4;
	((uint4*)dst->v)[2*threadIdx.x] =      src[2*MyPos       +  MyPlace*argon_memcost * 8];
	((uint4*)dst->v)[2*threadIdx.x +1 ] =  src[2*MyPos + 1   +  MyPlace*argon_memcost * 8];
}


__device__ __forceinline__ void xor_block(mem_blk *dst, const mem_blk *src) {
 
	((uint4*)dst->v)[2 * threadIdx.x] ^= ((uint4*)src->v)[2 * threadIdx.x];
	((uint4*)dst->v)[2 * threadIdx.x + 1] ^= ((uint4*)src->v)[2 * threadIdx.x + 1];
}

__device__ __forceinline__ void xor_block_sliced(mem_blk *dst, const uint4 *src) {
	int MyPlace = (threadIdx.x) / 4;
	int MyPos = (threadIdx.x) % 4;
	((uint4*)dst->v)[2 * threadIdx.x]	  ^= src[2 * MyPos + MyPlace*argon_memcost * 8];
	((uint4*)dst->v)[2 * threadIdx.x + 1] ^= src[2 * MyPos + 1 + MyPlace*argon_memcost * 8];
}



__device__ __forceinline__ uint64_t fBlaMka(uint64_t x, uint64_t y) {
//	const uint64_t m = UINT64_C(0xFFFFFFFF);
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

__device__ __forceinline__ void xor_copy_block_sliced(uint4 *dst, const mem_blk *src, const mem_blk *src1) {

	int MyPlace = (threadIdx.x) / 4;
	int MyPos = (threadIdx.x) % 4;
	dst[2 * MyPos +     MyPlace*argon_memcost * 8] = ((uint4*)src->v)[2 * threadIdx.x]     ^ ((uint4*)src1->v)[2 * threadIdx.x];
	dst[2 * MyPos + 1 + MyPlace*argon_memcost * 8] = ((uint4*)src->v)[2 * threadIdx.x + 1] ^ ((uint4*)src1->v)[2 * threadIdx.x + 1];


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
//	unsigned i;

	copy_block(&blockR, ref_block);

	xor_block(&blockR, prev_block);

	copy_block(&block_tmp, &blockR);

	if (with_xor) {
		xor_block(&block_tmp, next_block);

	}

	if (!tid) {

		blockR.v[14] = MAKE_ULONGLONG(TheIndex[0], TheIndex[1]);

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

//		int i = tid;
		int y = (tid >> 2) << 4;
		int x = tid & 3;
		/*
		uint64_t t[16];
		for(int i=0;i<16;i++)
		t[i]= blockR.v[y+i];
		*/

		G(blockR.v[y + x], blockR.v[y + 4 + x], blockR.v[y + 8 + x], blockR.v[y + 12 + x]);
		G(blockR.v[y + x], blockR.v[y + 4 + ((1 + x) & 3)], blockR.v[y + 8 + ((2 + x) & 3)], blockR.v[y + 12 + ((3 + x) & 3)]);

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

//		int i = tid;
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

	}
	__syncwarp();
	//}
	//	__syncthreads();
	//	xor_block(&block_tmp, &blockR);
	//	copy_block(next_block, &block_tmp);
	xor_copy_block(next_block, &block_tmp, &blockR);

	//xor_block(next_block, &blockR);
}


__device__ __forceinline__ void fill_block_withIndex_sliced(const uint4 *prev_block, const uint4 *ref_block,
	uint4 *next_block, int with_xor, uint32_t block_header[8], uint32_t index) {
	__shared__ mem_blk blockR;
	__shared__ mem_blk block_tmp;
	int tid = threadIdx.x;
	uint32_t TheIndex[2] = { 0,index };
//	unsigned i;

	copy_block_sliced(&blockR, ref_block);

	xor_block_sliced(&blockR, prev_block);

	copy_block(&block_tmp, &blockR);

	if (with_xor) {
		xor_block_sliced(&block_tmp, next_block);

	}

	if (!tid) {

		blockR.v[14] = MAKE_ULONGLONG(TheIndex[0], TheIndex[1]);

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

//		int i = tid;
		int y = (tid >> 2) << 4;
		int x = tid & 3;
		/*
		uint64_t t[16];
		for(int i=0;i<16;i++)
		t[i]= blockR.v[y+i];
		*/

		G(blockR.v[y + x], blockR.v[y + 4 + x], blockR.v[y + 8 + x], blockR.v[y + 12 + x]);
		G(blockR.v[y + x], blockR.v[y + 4 + ((1 + x) & 3)], blockR.v[y + 8 + ((2 + x) & 3)], blockR.v[y + 12 + ((3 + x) & 3)]);

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

//		int i = tid;
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

	}
	__syncwarp();
	//}
	//	__syncthreads();
	//	xor_block(&block_tmp, &blockR);
	//	copy_block(next_block, &block_tmp);
	xor_copy_block_sliced(next_block, &block_tmp, &blockR);

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
//	const uint32_t lanes = 4;
	uint32_t index;
	struct mem_blk * memory = (struct mem_blk *)DBlock;
//	int tid = threadIdx.x;
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
		ref_block =  memory + (ref_lane << 20) + ref_index;

		curr_block = memory + curr_offset;
		TheBlockIndex = (ref_lane << 20) + ref_index;

		fill_block_withIndex(memory + prev_offset, ref_block, curr_block, 0, BH, TheBlockIndex);

	}

}

template <const uint32_t slice>
__global__ __launch_bounds__(128, 1)
void mtp_i2(uint4  *  DBlock, uint32_t *block_header) {
	uint32_t prev_offset, curr_offset;
	//uint64_t pseudo_rand;
	uint64_t  ref_index, ref_lane;
	const uint32_t pass = 0;
	//uint32_t lane =threadIdx.x;
	uint32_t lane = blockIdx.x;
	const uint32_t lane_length = 1048576;
	const uint32_t segment_length = 262144;
//	const uint32_t lanes = 4;
	uint32_t index;
	uint4 * memory = &DBlock[0];
//	int tid = threadIdx.x;
	uint4 *ref_block = NULL, *curr_block = NULL;
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
		uint2  pseudo_rand2 = ((uint2*)(memory + prev_offset*8))[0]; //vectorize(memory[prev_offset].v[0]);

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
		ref_block = memory + ((ref_lane << 20) + ref_index)*8 ;

		curr_block = memory + curr_offset*8;
		TheBlockIndex = (ref_lane << 20) + ref_index;

		fill_block_withIndex_sliced(memory + prev_offset*8, ref_block, curr_block, 0, BH, TheBlockIndex);

	}

}



__global__ void mtp_fc(uint32_t threads, uint4  *  DBlock, uint2 *a) {
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads) {

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
			for (int j = 0; j<8; j++)DataTmp[j] = DataTmp2[j];
			//              DataTmp = DataTmp2;
			//                              if(thread == 1) printf("%x %x\n",DataChunk[0].lo.s0, DataTmp[0].x);;

		}
#pragma unroll
		for (int i = 0; i<2; i++)
			a[thread * 2 + i] = DataTmp[i];




	}
}

//
__global__  void mtp_fc2(uint32_t threads, uint4  *  DBlock, uint2 *a) {
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads) {

		const uint4 *    __restrict__ GBlock = &DBlock[0];
		uint32_t len = 0;
		uint2 DataTmp[8];
		for (int i = 0; i<8; i++)
			DataTmp[i] = blakeInit2[i];

		for (int i = 0; i < 8; i++) {
			//              len += (i&1!=0)? 32:128;
			len += 128;
			uint16 DataChunk[2];
			DataChunk[0].lo = ((uint8*)GBlock)[thread * 4 + 4 * i * argon_memcost + 0];
			DataChunk[0].hi = ((uint8*)GBlock)[thread * 4 + 4 * i * argon_memcost + 1];
			DataChunk[1].lo = ((uint8*)GBlock)[thread * 4 + 4 * i * argon_memcost + 2];
			DataChunk[1].hi = ((uint8*)GBlock)[thread * 4 + 4 * i * argon_memcost + 3];



			uint2 DataTmp2[8];
			blake2b_compress4x((uint2*)&DataTmp2, (uint2*)&DataTmp, (uint2*)DataChunk, len, i == 7);
			for (int j = 0; j<8; j++)DataTmp[j] = DataTmp2[j];
			//              DataTmp = DataTmp2;
			//                              if(thread == 1) printf("%x %x\n",DataChunk[0].lo.s0, DataTmp[0].x);;

		}
#pragma unroll
		for (int i = 0; i<2; i++)
			a[thread * 2 + i] = DataTmp[i];




	}
}



__host__ void get_tree(int thr_id, uint8_t* d, cudaStream_t s0) {
	cudaMemcpyAsync(d, buffer_a[thr_id], sizeof(uint2) * 2 * 1048576 * 4, cudaMemcpyDeviceToHost,s0);
}

__host__ uint8_t* get_tree2(int thr_id) {
	uint8_t *d; 
	cudaMallocHost(&d, sizeof(uint2) * 2 * 1048576 * 4);
	cudaMemcpy(d, buffer_a[thr_id], sizeof(uint2) * 2 * 1048576 * 4, cudaMemcpyDeviceToHost);
	return d;
}


__host__ void get_block(int thr_id, void* d, uint32_t index, cudaStream_t s0) {
//	cudaSetDevice(device_map[thr_id]);

//	cudaMemcpy(d, &HBlock[thr_id][64 * index], sizeof(uint64_t) * 128, cudaMemcpyDeviceToHost);

	for (int i = 0; i<8; i++) {
		uint4 *Blockptr = &HBlock[thr_id][index * 8 + i*argon_memcost * 8];
		cudaError_t err = cudaMemcpyAsync((uint64_t*)d + 16 * i,Blockptr,  32* sizeof(uint32_t), cudaMemcpyDeviceToHost,s0);
	}


}


__host__ void mtp_i_cpu(int thr_id, uint32_t *block_header, cudaStream_t s0) {

//	cudaSetDevice(device_map[thr_id]);
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

	mtp_i<0> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i<1> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i<2> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i<3> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);

	tpb = 256;
	dim3 grid2(1048576 * 4 / tpb);
	dim3 block2(tpb);
	mtp_fc << <grid2, block2, thr_id, s0 >> >(1048576 * 4, (uint4*)HBlock[thr_id], buffer_a[thr_id]);
	cudaStreamSynchronize(s0);

}


__host__ void mtp_i_cpu2(int thr_id, uint32_t *block_header, cudaStream_t s0) {

//	cudaSetDevice(device_map[thr_id]);
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

	mtp_i2<0> << <grid, block, thr_id,s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i2<1> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i2<2> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);
	mtp_i2<3> << <grid, block, thr_id, s0 >> >((uint4*)HBlock[thr_id], Header[thr_id]);
	cudaStreamSynchronize(s0);

	tpb = 256;
	dim3 grid2(1048576 * 4 / tpb);
	dim3 block2(tpb);
	mtp_fc2 << <grid2, block2, thr_id, s0 >> >(1048576 * 4, (uint4*)HBlock[thr_id], buffer_a[thr_id]);
	cudaStreamSynchronize(s0);

}



__host__
void mtp_fill_1b(int thr_id, uint64_t *Block, uint32_t block_nr, cudaStream_t s0)
{
//	cudaSetDevice(device_map[thr_id]);
	uint4 *Blockptr = &HBlock[thr_id][block_nr * 64];
	cudaError_t err = cudaMemcpyAsync(Blockptr, Block, 256 * sizeof(uint32_t), cudaMemcpyHostToDevice, s0);
//subdivide blocks in 8 units of 128

	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}

}

__host__
void mtp_fill_1c(int thr_id, uint64_t *Block, uint32_t block_nr, cudaStream_t s0)
{
//	cudaSetDevice(device_map[thr_id]);
	//	uint4 *Blockptr = &HBlock[thr_id][block_nr * 64];
	//	cudaError_t err = cudaMemcpy(Blockptr, Block, 256 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	//subdivide blocks in 8 units of 128
	cudaError_t err = cudaSuccess;
	for (int i = 0; i<8; i++) {
		uint4 *Blockptr = &HBlock[thr_id][block_nr * 8 + i*argon_memcost * 8];
		err = cudaMemcpyAsync(Blockptr, Block + 16 * i, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice, s0);
	}
	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}

}