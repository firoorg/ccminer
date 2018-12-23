

#include "argon2ref/argon2.h"
#include "merkletree/mtp.h"

#include <unistd.h>
#include "miner.h"
#include "cuda_helper.h"
#define memcost 4*1024*1024

extern void mtp_cpu_init(int thr_id, uint32_t threads);

extern uint32_t mtp_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce);

extern void mtp_setBlockTarget(int thr_id,const void* pDataIn, const void *pTargetIn, const void * zElement);
extern void mtp_fill(uint32_t d, const uint64_t *Block, uint32_t offset, uint32_t datachunk);

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"
//#define MTP_L 64

static bool init[MAX_GPUS] = { 0 };
static __thread uint32_t throughput = 0;
static uint32_t JobId = 0;
static uint64_t XtraNonce2 = 0;
static bool fillGpu[MAX_GPUS] = {false};
static  MerkleTree::Elements TheElements;
static  MerkleTree ordered_tree;
static  unsigned char TheMerkleRoot[16];
static  argon2_context context;
static argon2_instance_t instance;
static pthread_mutex_t work_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
extern "C" int scanhash_mtp(int nthreads,int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done, struct mtp* mtp,struct work* gwork)
{

	unsigned char mtpHashValue[32];



if (JobId==0)
	pthread_barrier_init(&barrier, NULL, nthreads);


	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	int real_maxnonce = UINT32_MAX / nthreads * (thr_id + 1);

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

		uint32_t diff = 5;
		uint32_t TheNonce;

	if (!init[thr_id])
	{
	int dev_id = device_map[thr_id];;
		cudaSetDevice(dev_id);
		
		cudaDeviceReset();
		cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
//		cudaSetDeviceFlags(cudaDeviceScheduleYield);

		int intensity = 16;
		throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
//		throughput =  1024*64;
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
	

	if (JobId != work->data[17] || XtraNonce2!= ((uint64_t*)work->xnonce2)[0]) {
pthread_barrier_wait(&barrier);
	}
pthread_mutex_lock(&work_lock);

if (JobId!= work->data[17] || XtraNonce2 != ((uint64_t*)work->xnonce2)[0]){

if (JobId!=0)
	free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));


	context = init_argon2d_param((const char*)endiandata);
	argon2_ctx_from_mtp(&context, &instance);
//	printf("extranonce2 %llx  XtraNonce2 %llx thread_id %d\n", ((uint64_t*)work->xnonce2)[0], XtraNonce2,thr_id);

    TheElements = mtp_init2(&instance);

	ordered_tree = MerkleTree(TheElements, true);
	JobId = work->data[17];
	XtraNonce2 = ((uint64_t*)work->xnonce2)[0];

	MerkleTree::Buffer root = ordered_tree.getRoot();
	std::copy(root.begin(), root.end(), TheMerkleRoot);

for (int i=0;i<nthreads;i++) {
	mtp_setBlockTarget(i,endiandata,ptarget,&TheMerkleRoot);
for (int i=0;i<nthreads;i++)
	fillGpu[i] = true;
}

printf("filling memory\n");
const int datachunk = 512;
for (int i=0;i<((uint32_t)memcost/ datachunk);i++) {
uint64_t *Truc =(uint64_t *) malloc(128* datachunk*sizeof(uint64_t));
	
	for (int j=0;j<datachunk;j++)
		memcpy(&Truc[128*j],instance.memory[datachunk*i+j].v,128*sizeof(uint64_t));
for (int k=0;k<nthreads;k++)
	mtp_fill(k,Truc, i, datachunk);

	free(Truc);
}
printf("memory filled \n");


}

pthread_mutex_unlock(&work_lock);
/*
if (fillGpu[thr_id]) {

printf("filling memory\n");
const int datachunk = 512;
for (int i = 0; i<((uint32_t)memcost / datachunk) // && !work_restart[thr_id].restart; i++) {
	uint64_t *Truc = (uint64_t *)malloc(128 * datachunk * sizeof(uint64_t));

	for (int j = 0; j<datachunk; j++)
		memcpy(&Truc[128 * j], instance.memory[datachunk*i + j].v, 128 * sizeof(uint64_t));
	
		mtp_fill(thr_id, Truc, i, datachunk);

	free(Truc);
}
printf("memory filled \n");
fillGpu[thr_id]=false;
}

*/
	if (work_restart[thr_id].restart) goto TheEnd;
		pdata[19] = first_nonce;
//do  {
//		printf("work->data[17]=%08x\n", work->data[17]);
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

//	}   while (!work_restart[thr_id].restart   && pdata[19]<real_maxnonce && JobId==work->data[17] && XtraNonce2 == ((uint64_t*)work->xnonce2)[0]);//*&& pdata[19]<(first_nonce+128*throughput)*/);

TheEnd:
		pthread_mutex_lock(&work_lock);
		if (pdata[19] >= real_maxnonce)
			for (int i = 0; i < (int)gwork->xnonce2_len && !++gwork->xnonce2[i]; i++);

		pthread_mutex_unlock(&work_lock);

	*hashes_done = pdata[19] - first_nonce;


	return 0;
}


