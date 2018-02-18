//
// Created by aizen on 4/09/17.
//

#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#endif //ZCOIN_MTP_H

//#include "main.h"
//#include "merkletree/merkletree.h"
#include "bignum.hpp"
#include "merkletree.hpp"
//#include <immintrin.h>
#include "argon2ref/core.h"
#include "argon2ref/argon2.h"
#include "argon2ref/thread.h"
#include "argon2ref/blake2.h"
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blamka-round-opt.h"
//#include "merkletree/sha.h"

#include "openssl\sha.h"

#include "uint256.h"

class CBlock;

/* Size of MTP proof */
const unsigned int MTP_PROOF_SIZE = 1431;
/* Size of MTP block proof size */
const unsigned int MTP_BLOCK_PROOF_SIZE = 70;
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



void mtp_hash(char* output, const char* input, unsigned int d, uint32_t TheNonce);
argon2_context init_argon2d_param(const char* input);

int mtp_init(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, uint256 &resultMerkleRoot);
int mtp_solver_withblock(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, block_mtpProof *output, uint256 resultMerkleRoot, merkletree TheTree, uint256 hashTarget);
merkletree mtp_init_withtree(argon2_instance_t *instance,  uint256 &resultMerkleRoot);
