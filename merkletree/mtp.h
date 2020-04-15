//
//

#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#endif //ZCOIN_MTP_H



#include "merkle-tree.hpp"

#include <immintrin.h>
#include "argon2ref/core.h"
#include "argon2ref/argon2.h"
#include "argon2ref/thread.h"
#include "argon2ref/blake2.h"
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blamka-round-opt.h"
//#include "merkletree/sha.h"

//#include "openssl\sha.h"
#include <cuda.h>
#include <cuda_runtime.h>

#include "uint256.h"
//#include "serialize.h"
class CBlock;

/* Size of MTP proof */
const unsigned int MTP_PROOF_SIZE = 1471;// 1431;
/* Size of MTP block proof size */
const unsigned int MTP_BLOCK_PROOF_SIZE = 64;
/* Size of MTP block */
const unsigned int MTP_BLOCK_SIZE = 140;

typedef struct block_with_offset_ {
	block memory;
	//	char* proof;
	char proof[MTP_PROOF_SIZE];
} block_with_offset;

typedef struct block_mtpProof_ {
	block memory;
	char proof[MTP_PROOF_SIZE];
} block_mtpProof;

typedef struct mtp_Proof_ {
	char proof[MTP_PROOF_SIZE]; 
} mtp_Proof;

void copy_blockS(blockS *dst, const block *src);

void mtp_hash(char* output, const char* input, unsigned int d, uint32_t TheNonce);
argon2_context init_argon2d_param(const char* input);
void getblockindex_orig(uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_block);

void getblockindex(int thr_id, uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_block, cudaStream_t s0);


//int mtp_solver_withblock(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, block_mtpProof *output,
// uint8_t *resultMerkleRoot, MerkleTree TheTree,uint32_t* input, uint256 hashTarget);

int mtp_solver_orig(uint32_t TheNonce, argon2_instance_t *instance,
	blockS *nBlockMTP /*[72 * 2][128]*/, unsigned char *nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree TheTree, uint32_t* input, uint256 hashTarget);

int mtp_solver(int thr_id, uint32_t TheNonce, argon2_instance_t *instance,
	blockS *nBlockMTP /*[72 * 2][128]*/, unsigned char *nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree TheTree, uint32_t* input, uint256 hashTarget, cudaStream_t s0);




MerkleTree::Elements mtp_init(argon2_instance_t *instance);
MerkleTree::Elements mtp_init2(argon2_instance_t *instance);
//uint8_t *mtp_init3(argon2_instance_t *instance, int thr_id);
//void  mtp_init3(argon2_instance_t *instance, int thr_id, MerkleTree *TheTree);
//MerkleTree  mtp_init3(argon2_instance_t *instance, int thr_id);
void  mtp_init3(argon2_instance_t *instance, int thr_id, MerkleTree &ThatTree);