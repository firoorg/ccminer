extern "C" {
#include "sph/sph_blake.h"
#include "sph/sph_groestl.h"
#include "sph/sph_skein.h"
#include "sph/sph_keccak.h"
#include "lyra2/Lyra2.h"
}

#include "miner.h"
#include "cuda_helper.h"

static uint64_t* d_hash[MAX_GPUS];
static uint64_t* d_matrix[MAX_GPUS];

extern void blake256_cpu_init(int thr_id, uint32_t threads);
extern void blake256_cpu_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNonce, uint64_t *Hash, int order);
extern void blake256_cpu_setBlock_80(uint32_t *pdata);

extern void keccak256_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNonce, uint64_t *d_outputHash, int order);
extern void keccak256_cpu_init(int thr_id, uint32_t threads);
extern void keccak256_cpu_free(int thr_id);
extern void skein256_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNonce, uint64_t *d_outputHash, int order);
extern void skein256_cpu_init(int thr_id, uint32_t threads);

extern void lyra2Z_cpu_init(int thr_id, uint32_t threads, uint64_t *d_matrix);
extern void lyra2Z_cpu_init_sm2(int thr_id, uint32_t threads);
extern uint32_t lyra2Z_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNonce, uint64_t *d_outputHash, bool gtx750ti);

extern void lyra2Z_setTarget(const void *ptarget);
extern uint32_t lyra2Z_getSecNonce(int thr_id, int num);

#ifdef _DEBUG
#define TRACE(algo) { \
	if (max_nonce == 1 && pdata[19] <= 1) { \
		uint32_t* debugbuf = NULL; \
		cudaMallocHost(&debugbuf, 8*sizeof(uint32_t)); \
		cudaMemcpy(debugbuf, d_hash[thr_id], 8*sizeof(uint32_t), cudaMemcpyDeviceToHost); \
		printf("lyra %s %08x %08x %08x %08x...\n", algo, swab32(debugbuf[0]), swab32(debugbuf[1]), \
			swab32(debugbuf[2]), swab32(debugbuf[3])); \
		cudaFreeHost(debugbuf); \
	} \
}
#else
#define TRACE(algo) {}
#endif

extern "C" void lyra2Z_hash(void *state, const void *input)
{
	uint32_t hashA[8], hashB[8];

	sph_blake256_context     ctx_blake;
	sph_blake256_set_rounds(14);

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);
 
	LYRA2(hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);
 
	memcpy(state, hashB, 32);
}

static bool init[MAX_GPUS] = { 0 };
static __thread uint32_t throughput = 0;

extern "C" int scanhash_lyra2Z(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	static __thread bool gtx750ti;
	if (!init[thr_id])
	{
		int dev_id = device_map[thr_id];
		cudaSetDevice(dev_id);
		CUDA_LOG_ERROR();
		cudaDeviceReset();
		cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);

		int intensity = (device_sm[dev_id] >= 500 && !is_windows()) ? 17 : 16;
		if (device_sm[device_map[thr_id]] == 500) intensity = 15;
		throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
		if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

		cudaDeviceProp props;
		cudaGetDeviceProperties(&props, dev_id);

		if (strstr(props.name, "750 Ti")) gtx750ti = true;
		else gtx750ti = false;

		gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

		blake256_cpu_init(thr_id, throughput);

		if (device_sm[dev_id] >= 350)
		{
			size_t matrix_sz = device_sm[dev_id] > 500 ? sizeof(uint64_t) * 4 * 4 : sizeof(uint64_t) * 8 * 8 * 3 * 4;
			CUDA_SAFE_CALL(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));
			lyra2Z_cpu_init(thr_id, throughput, d_matrix[thr_id]);
		}
		else 
			lyra2Z_cpu_init_sm2(thr_id, throughput);
 

		CUDA_SAFE_CALL(cudaMalloc(&d_hash[thr_id], (size_t)32 * throughput));

		init[thr_id] = true;
	}

	uint32_t _ALIGN(128) endiandata[20];
	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	blake256_cpu_setBlock_80(pdata);
	lyra2Z_setTarget(ptarget);

	do {
		int order = 0;
		uint32_t foundNonce;

		blake256_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);

		*hashes_done = pdata[19] - first_nonce + throughput;

		foundNonce = lyra2Z_cpu_hash_32(thr_id, throughput, pdata[19], d_hash[thr_id], gtx750ti); 

		if (foundNonce != UINT32_MAX)
		{
			uint32_t _ALIGN(64) vhash64[8];

			be32enc(&endiandata[19], foundNonce); 
			lyra2Z_hash(vhash64, endiandata);  

			if (vhash64[7] <= ptarget[7] && fulltest(vhash64, ptarget)) {
				int res = 1;
			
				uint32_t secNonce = lyra2Z_getSecNonce(thr_id, 1);
				work_set_target_ratio(work, vhash64);
				if (secNonce != UINT32_MAX)
				{
					be32enc(&endiandata[19], secNonce);
					lyra2Z_hash(vhash64, endiandata);
					if (vhash64[7] <= ptarget[7] && fulltest(vhash64, ptarget)) {
						if (opt_debug)
							gpulog(LOG_BLUE, thr_id, "found second nonce %08x", secNonce);
						if (bn_hash_target_ratio(vhash64, ptarget) > work->shareratio[0])
							work_set_target_ratio(work, vhash64);
						pdata[21] = secNonce;
						res++;
					}
				}
			
				pdata[19] = foundNonce;
				return res;
			} else {
				gpulog(LOG_WARNING, thr_id, "result for %08x does not validate on CPU!", foundNonce);
			}
		}

		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
		pdata[19] += throughput;

	} while (!work_restart[thr_id].restart);

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}

// cleanup
extern "C" void free_lyra2Z(int thr_id)
{
	if (!init[thr_id])
		return;

	cudaThreadSynchronize();

	cudaFree(d_hash[thr_id]);
	cudaFree(d_matrix[thr_id]);
	init[thr_id] = false;

	cudaDeviceSynchronize();
}
