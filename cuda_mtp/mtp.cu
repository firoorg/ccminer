

#include "argon2ref/argon2.h"
#include "merkletree/mtp.h"

#include <unistd.h>
#include "miner.h"
#include "cuda_helper.h"
#define memcost 4*1024*1024

extern void mtp_cpu_init(int thr_id, uint32_t threads);

extern uint32_t mtp_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce);

extern void mtp_setBlockTarget(const void* pDataIn, const void *pTargetIn, const void * zElement);
extern void mtp_fill(const uint64_t *Block, uint32_t offset, uint32_t datachunk);

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"
//#define MTP_L 64

static bool init[MAX_GPUS] = { 0 };
static __thread uint32_t throughput = 0;
static uint32_t JobId = 0;
static MerkleTree::Elements TheElements;
static MerkleTree ordered_tree;
static unsigned char TheMerkleRoot[16];
static argon2_context context;
argon2_instance_t instance;
extern "C" int scanhash_mtp(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done, struct mtp* mtp)
{
//	if (work_restart[thr_id].restart) return 0;
//	unsigned char TheMerkleRoot[16];
	unsigned char mtpHashValue[32];
//	MerkleTree::Elements TheElements; // = new MerkleTree;
printf("the job_id from mtp %s\n",work->job_id+8);
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	int dev_id;
	if (opt_benchmark)
		ptarget[7] = 0x00ff;

		uint32_t diff = 5;
		uint32_t TheNonce;

	if (!init[thr_id])
	{
		dev_id = device_map[thr_id];
		cudaSetDevice(dev_id);
		
		cudaDeviceReset();
//		cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
//		cudaSetDeviceFlags(cudaDeviceScheduleYield);

		int intensity = (device_sm[dev_id] >= 500 && !is_windows()) ? 17 : 16;
		if (device_sm[device_map[thr_id]] == 500) intensity = 15;
		intensity = 1;
		throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
		throughput =  1024*64;
		if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

		cudaDeviceProp props;
		cudaGetDeviceProperties(&props, dev_id);


		gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);


		mtp_cpu_init(thr_id, throughput);

		init[thr_id] = true;

	}

	uint32_t _ALIGN(128) endiandata[20];
	((uint32_t*)pdata)[19] = (pdata[20]); //*/0x00100000; // mtp version not the actual nonce
//	((uint32_t*)pdata)[19] = 0x1000;

	for (int k = 0; k < 20; k++) 
		endiandata[k] = pdata[k];
	
//	argon2_context context = init_argon2d_param((const char*)endiandata);
//	argon2_instance_t instance;
//	argon2_ctx_from_mtp(&context, &instance);


printf("Pdata1 %08x work->data[1] %08x\n", JobId,work->data[17]);
if (JobId!= work->data[17]){

if (JobId!=0)
	free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));

	context = init_argon2d_param((const char*)endiandata);
	argon2_ctx_from_mtp(&context, &instance);


	TheElements = mtp_init(&instance);
//	MerkleTree ordered_tree;
	ordered_tree = MerkleTree(TheElements, true);
	JobId = work->data[17];

	MerkleTree::Buffer root = ordered_tree.getRoot();
	std::copy(root.begin(), root.end(), TheMerkleRoot);

	mtp_setBlockTarget(endiandata,ptarget,&TheMerkleRoot);
const int datachunk = 512;
	if (work_restart[thr_id].restart) goto TheEnd;

printf("filling memory\n");

for (int i=0;i<(memcost/ datachunk) && !work_restart[thr_id].restart;i++) {
uint64_t *Truc =(uint64_t *) malloc(128* datachunk*sizeof(uint64_t));
	
	for (int j=0;j<datachunk;j++)
		memcpy(&Truc[128*j],instance.memory[datachunk*i+j].v,128*sizeof(uint64_t));

	mtp_fill(Truc, i, datachunk);
	free(Truc);
}
printf("memory filled \n");
}

	if (work_restart[thr_id].restart) goto TheEnd;
		pdata[19] = first_nonce;
do  {
		int order = 0;
		uint32_t foundNonce;

		*hashes_done = pdata[19] - first_nonce + throughput;
	  
		foundNonce = mtp_cpu_hash_32(thr_id, throughput, pdata[19]);

		uint32_t _ALIGN(64) vhash64[8];
		if (foundNonce != UINT32_MAX)
		{

			block_mtpProof TheBlocksAndProofs[140];
			uint256 TheUint256Target[1];
			TheUint256Target[0] = ((uint256*)ptarget)[0];

			blockS nBlockMTP[MTP_L *2];
			unsigned char nProofMTP[MTP_L * 3 * 353 ];
			
			uint32_t is_sol = mtp_solver(foundNonce, &instance, nBlockMTP,nProofMTP, TheMerkleRoot, mtpHashValue, ordered_tree, endiandata,TheUint256Target[0]);

			if (is_sol==1 /*&& fulltest(vhash64, ptarget)*/) {
				int res = 1;
				work_set_target_ratio(work, vhash64);		

				pdata[19] =/*swab32*/(foundNonce);

/// fill mtp structure
				mtp->MTPVersion = 0x1000;
			for (int i=0;i<16;i++) 
				mtp->MerkleRoot[i] = TheMerkleRoot[i];
			for (int i = 0; i<32; i++)
				mtp->mtpHashValue[i] = mtpHashValue[i];
			
			for (int j=0;j<(MTP_L * 2);j++)
				for (int i=0;i<128;i++)
				mtp->nBlockMTP[j][i]= nBlockMTP[j].v[i];
                int lenMax =0; 
				int len = 0;

				memcpy(mtp->nProofMTP, nProofMTP, sizeof(unsigned char)* MTP_L * 3 * 353);


				printf("found a solution, nonce %08x\n",pdata[19]);
//				free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
				
				return res;

			} else {
				gpulog(LOG_WARNING, thr_id, "result for %08x does not validate on CPU!", foundNonce);
			}
		}
		work_set_target_ratio(work, vhash64);
/*
		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
*/
		pdata[19] += throughput;
//		be32enc(&endiandata[19], pdata[19]);
	}   while (!work_restart[thr_id].restart && pdata[19]<0xffffffff);

TheEnd:
//	free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
	*hashes_done = pdata[19] - first_nonce;

//	ordered_tree.~MerkleTree();
//	TheElements.clear();
	return 0;
}


