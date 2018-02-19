//
// Created by aizen on 4/9/17.
//
#pragma once 
#include "mtp.h"
#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif

#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

static const unsigned int d_mtp = 1;
static const uint8_t L = 70;
static const unsigned int memory_cost = 2097152*1;


unsigned int trailing_zeros(char str[64]) {


    unsigned int i, d;
    d = 0;
    for (i = 63; i > 0; i--) {
        if (str[i] == '0') {
            d++;
        }
        else {
            break;
        }
    }
    return d;
}


unsigned int trailing_zeros_little_endian(char str[64]) {
	unsigned int i, d;
	d = 0;
	for (i = 0; i < 64; i++) {
		if (str[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}

unsigned int trailing_zeros_little_endian_uint256(uint256 hash) {
	unsigned int i, d;
	string temp = hash.GetHex();
	d = 0;
	for (i = 0; i < temp.size(); i++) {
		if (temp[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}


static void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}


void fill_block(__m128i *state, const block *ref_block, block *next_block, int with_xor) {
    __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
            block_XY[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
        }
    }
    else {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
        }
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }

    for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
    }
}

void fill_block2(__m128i *state, const block *ref_block, block *next_block, int with_xor, uint32_t block_header[4]) {
	__m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
	unsigned int i;

	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
			block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
		}
	}

	memcpy(&state[8], block_header, sizeof(__m128i));

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
		state[i] = _mm_xor_si128(state[i], block_XY[i]);
		_mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
	}
}

void fill_block2_withIndex(__m128i *state, const block *ref_block, block *next_block, int with_xor, uint32_t block_header[8], uint64_t blockIndex) {
	__m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
	unsigned int i;
    uint64_t TheIndex[2]={0,blockIndex};
	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
			block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
		}
	}
	memcpy(&state[7], TheIndex, sizeof(__m128i));
	memcpy(&state[8], block_header, sizeof(__m128i));
	memcpy(&state[9], block_header + 4, sizeof(__m128i));
	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
		state[i] = _mm_xor_si128(state[i], block_XY[i]);
		_mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
	}
}



void copy_block(block *dst, const block *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}
#define VC_GE_2005(version) (version >= 1400)

void  secure_wipe_memory(void *v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
	SecureZeroMemory(v, n);
#elif defined memset_s
	memset_s(v, n, 0, n);
#elif defined(__OpenBSD__)
	explicit_bzero(v, n);
#else
	static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
	memset_sec(v, 0, n);
#endif
}

/* Memory clear flag defaults to true. */

void clear_internal_memory(void *v, size_t n) {
	if (FLAG_clear_internal_memory && v) {
		secure_wipe_memory(v, n);
	}
}


void free_memory(const argon2_context *context, uint8_t *memory,
	size_t num, size_t size) {
	size_t memory_size = num*size;
	clear_internal_memory(memory, memory_size);
	if (context->free_cbk) {
		(context->free_cbk)(memory, memory_size);
	}
	else {
		free(memory);
	}
}

argon2_context init_argon2d_param(const char* input) {

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0
    argon2_context context;
    argon2_context *pContext = &context;

    unsigned char out[TEST_OUTLEN];
    //unsigned char pwd[TEST_PWDLEN];
    //unsigned char salt[TEST_SALTLEN]; 
	//    unsigned char secret[TEST_SECRETLEN];
	//   unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 1;
    unsigned m_cost =  2*1024*1024; //+896*1024; //32768*1;
    unsigned lanes = 4;

    memset(pContext,0,sizeof(argon2_context));
    memset(&out[0], 0, sizeof(out));
    //memset(&pwd[0], nHeight + 1, TEST_OUTLEN);
    //memset(&salt[0], 2, TEST_SALTLEN);
    //memset(&secret[0], 3, TEST_SECRETLEN); 
    //memset(&ad[0], 4, TEST_ADLEN);

    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.version = ARGON2_VERSION_NUMBER;
    context.pwd = (uint8_t*)input;
    context.pwdlen = TEST_PWDLEN;
    context.salt = (uint8_t*)input;
    context.saltlen = TEST_SALTLEN;
    context.secret = NULL;
    context.secretlen = TEST_SECRETLEN;
    context.ad = NULL;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    return context;
}

int mtp_solver_withblock(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, block_mtpProof *output, uint256 resultMerkleRoot, merkletree TheTree, uint256 hashTarget) {



	if (instance != NULL) {
	
		uint512 Y[71];
		memset(&Y, 0, sizeof(Y));
/*
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &resultMerkleRoot, sizeof(uint256));
		SHA256_Update(&ctx, &TheNonce, sizeof(unsigned int));
		SHA256_Final((unsigned char*)&Y[0], &ctx);
*/	


		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);
		ablake2b_update(&BlakeHash, &resultMerkleRoot, sizeof(uint256));
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y[0], 32);


	printf("\n cpu first blake");
	for (int n = 0; n < 16; n++) {
		printf(" %08x ", ((uint32_t*)&Y[0])[n]);
		//                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
	}
	printf("\n");


		///////////////////////////////
		bool init_blocks = false;
		bool unmatch_block = false;
		for (uint8_t j = 1; j <= L; j++) {
			uint32_t ij = ((uint32_t*)(&Y[j - 1]))[0] % (instance->context_ptr->m_cost);
	
			if (ij == 0 || ij == 1) {
				init_blocks = true;
				break;
			}

			block X_IJ;

			__m128i state_test[64];
			memset(state_test, 0, sizeof(state_test));
			memcpy(state_test, &instance->memory[instance->memory[ij].prev_block & 0xffffffff].v, ARGON2_BLOCK_SIZE);
			fill_block2_withIndex(state_test, &instance->memory[instance->memory[ij].ref_block], &X_IJ, 0,instance->block_header, instance->memory[ij].ref_block);
			X_IJ.prev_block = instance->memory[ij].prev_block;
			X_IJ.ref_block = instance->memory[ij].ref_block;


			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance->memory[ij]);

			int countIndex;
			for (countIndex = 0; countIndex < 128; countIndex++) {
				if (X_IJ.v[countIndex] != instance->memory[ij].v[countIndex]) {
					unmatch_block = true;
					break;
				}
			}
			//				printf("coming here 1\n");
			store_block(&blockhash_bytes, &blockhash);
/*
			SHA256_CTX ctx_yj;
			SHA256_Init(&ctx_yj);
			SHA256_Update(&ctx_yj, &Y[j - 1], sizeof(uint256));
			SHA256_Update(&ctx_yj, blockhash_bytes, ARGON2_BLOCK_SIZE);
			SHA256_Final((unsigned char*)&Y[j], &ctx_yj);
*/

			ablake2b_state BlakeHash2;
			ablake2b_init(&BlakeHash2, ARGON2_PREHASH_DIGEST_LENGTH / 2);
			ablake2b_update(&BlakeHash2, &Y[j - 1], sizeof(uint256));
			ablake2b_update(&BlakeHash2, blockhash_bytes, ARGON2_BLOCK_SIZE);
			ablake2b_final(&BlakeHash2, (unsigned char*)&Y[j], ARGON2_PREHASH_DIGEST_LENGTH / 2);


////////////////////////////////////////////////////////////////
// current block
	
			block blockhash_current;
			uint8_t blockhash_bytes_current[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_current, &instance->memory[ij]);
			store_block(&blockhash_bytes_current, &blockhash_current);
/*
			SHA256_CTX ctx_current;
			SHA256_Init(&ctx_current);
			SHA256_Update(&ctx_current, blockhash_bytes_current, ARGON2_BLOCK_SIZE);
			
			SHA256_Final((unsigned char*)&t_current, &ctx_current);
*/
			uint512 t_current;
			ablake2b_state ctx_current;
			ablake2b_init(&ctx_current, ARGON2_PREHASH_DIGEST_LENGTH/2);
			ablake2b_update(&ctx_current, blockhash_bytes_current, ARGON2_BLOCK_SIZE);
			ablake2b_final(&ctx_current, (unsigned char*)&t_current, ARGON2_PREHASH_DIGEST_LENGTH/2);

			clear_internal_memory(blockhash_current.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_bytes_current, ARGON2_BLOCK_SIZE);
		
			vector<ProofNode> newproof_current = TheTree.proof(t_current.trim256());

			char* buffer_current = serializeMTP(newproof_current);
			memcpy(&output[j - 1].proof, buffer_current, newproof_current.size() * NODE_LENGTH + 1);
			free(buffer_current);


/* save block_with_offset for previous block */
			copy_block(&output[(j * 2) - 1].memory, &instance->memory[instance->memory[ij].prev_block & 0xffffffff]);
			output[(j * 2) - 1].memory.prev_block = (instance->memory[instance->memory[ij].prev_block & 0xffffffff].prev_block) & 0xffffffff;
			output[(j * 2) - 1].memory.ref_block = instance->memory[instance->memory[ij].prev_block & 0xffffffff].ref_block;

			block blockhash_previous;
			uint8_t blockhash_bytes_previous[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_previous, &instance->memory[instance->memory[ij].prev_block & 0xffffffff]);
			store_block(&blockhash_bytes_previous, &blockhash_previous);
			/* generate proof with prev block */
/*
			SHA256_CTX ctx_previous;
			SHA256_Init(&ctx_previous);
			SHA256_Update(&ctx_previous, blockhash_bytes_previous, ARGON2_BLOCK_SIZE);
			uint256 t_previous;
			SHA256_Final((unsigned char*)&t_previous, &ctx_previous);
*/
			uint512 t_previous;
			ablake2b_state ctx_previous;
			ablake2b_init(&ctx_previous, ARGON2_PREHASH_DIGEST_LENGTH/2);
			ablake2b_update(&ctx_previous, blockhash_bytes_previous, ARGON2_BLOCK_SIZE);
			ablake2b_final(&ctx_previous, (unsigned char*)&t_previous, ARGON2_PREHASH_DIGEST_LENGTH/2);



			vector<ProofNode> newproof = TheTree.proof(t_previous.trim256());
			/*    store proof    */
			char* buffer = serializeMTP(newproof);
			memcpy(output[(j * 2) - 1].proof, buffer_current, newproof.size() * NODE_LENGTH + 1);
			free(buffer);
			
			/*    end            */
//////////////////////////////////////////////////////////////////
/* save block_with_offset for ref block */
			copy_block(&output[(j * 2) - 2].memory, &instance->memory[instance->memory[ij].ref_block]);
			output[(j * 2) - 2].memory.prev_block = instance->memory[instance->memory[ij].ref_block].prev_block & 0xffffffff;
			output[(j * 2) - 2].memory.ref_block = instance->memory[instance->memory[ij].ref_block].ref_block;

			block blockhash_ref_block;
			uint8_t blockhash_bytes_ref_block[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_ref_block, &instance->memory[instance->memory[ij].ref_block]);
			store_block(&blockhash_bytes_ref_block, &blockhash_ref_block);
/*
			SHA256_CTX ctx_ref;
			SHA256_Init(&ctx_ref);
			SHA256_Update(&ctx_ref, blockhash_bytes_ref_block, ARGON2_BLOCK_SIZE);
			uint256 t_ref_block;
			SHA256_Final((unsigned char*)&t_ref_block, &ctx_ref);
*/
			uint512 t_ref_block;
			ablake2b_state ctx_ref;
			ablake2b_init(&ctx_ref, ARGON2_PREHASH_DIGEST_LENGTH/2);
			ablake2b_update(&ctx_ref, blockhash_bytes_ref_block, ARGON2_BLOCK_SIZE);
			ablake2b_final(&ctx_ref, (unsigned char*)&t_ref_block, ARGON2_PREHASH_DIGEST_LENGTH/2);




			vector<ProofNode> newproof_ref = TheTree.proof(t_ref_block.trim256());

			char* buff = serializeMTP(newproof_ref);
			memcpy(output[(j * 2) - 2].proof, buff, newproof_ref.size() * NODE_LENGTH  + 1);
			free(buff);


/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
		}

		if (init_blocks) {
			//                printf("Step 5.1 : init_blocks \n");
			return 0;
		}
		//			printf("coming here 2\n");
		if (unmatch_block) {
			//                printf("Step 5.2 : unmatch_block \n");
			return 0;
		}
		//			printf("coming here 3\n");
		char hex_tmp[64];
		/*
		for (int n = 0; n < 32; n++) {
		//				printf(" %02x ", Y[L][n]);
		sprintf(&hex_tmp[n * 2], "%02x", ((unsigned char*)&Y)[n]);
		}
		*/
		if (Y[L].trim256() > hashTarget) {

		}
		else {

			// Found a solution
			printf("****************************************************Current hash: Nonce=%08x\n", TheNonce);
			printf("Found a solution. Hash:");
			for (int n = 0; n < 32; n++) {
				printf("%02x", ((unsigned char*)&Y[L])[n]);
			}
			printf("\n");
			for (int n = 0; n < 8; n++) {
				printf(" %08x ", ((uint32_t*)&Y[L])[n]);
				//                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
			}
			printf("\n");
			// TODO: copy hash to output
			//				memcpy(output, Y[L], 32);
			printf("Y[L] = %s\n", Y[L].trim256().GetHex().c_str());
			return 1;
			//printf("O-2\n");
		}
		//printf("O-3\n");

		//		} // while(true)
		//printf("O-4\n");
	}
	//printf("O-5\n");



	return 0;
}

int mtp_init(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, uint256 &resultMerkleRoot) {
	//internal_kat(instance, r); /* Print all memory blocks */
	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
	// Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory

	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
//		vector<char*> leaves((instance->context_ptr->m_cost)); // 2gb
		vector<uint256> leaves(0); // 2gb
		for (int i = 0; i < instance->memory_blocks; ++i) {
			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance->memory[i]);
			store_block(&blockhash_bytes, &blockhash);
			// hash each block with sha256
/*
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			uint256 hashBlock;
			SHA256_Update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
			SHA256_Final((unsigned char*)&hashBlock, &ctx);
*/
			uint512 hashBlock;
			ablake2b_state ctx;
			ablake2b_init(&ctx, ARGON2_PREHASH_DIGEST_LENGTH);
			ablake2b_update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
			ablake2b_final(&ctx, (unsigned char*)&hashBlock, ARGON2_PREHASH_DIGEST_LENGTH);

			leaves.push_back(hashBlock.trim256());

		
		}

		//		mt_hash_t resultMerkleRoot;
		int ret;
//		ret = mt_get_root(mt, resultMerkleRoot);

printf("after main loop\n");
		merkletree mtree = merkletree(leaves);

	//	leaves.clear();
printf("after merkletree \n");
		resultMerkleRoot = mtree.root();


printf("after obtening the root\n");
	}

		return 1;

}
//
merkletree mtp_init_withtree( argon2_instance_t *instance, uint256 &resultMerkleRoot) {
	//internal_kat(instance, r); /* Print all memory blocks */
	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
	// Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory
	merkletree mtree;
	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
		//		vector<char*> leaves((instance->context_ptr->m_cost)); // 2gb
		vector<uint256> leaves(0); // 2gb
		for (int i = 0; i < instance->memory_blocks; ++i) {
			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance->memory[i]);
			store_block(&blockhash_bytes, &blockhash);
			// hash each block with sha256
/*
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			//			uint8_t hashBlock[32];
			uint256 hashBlock;
			SHA256_Update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
			SHA256_Final((unsigned char*)&hashBlock, &ctx);
*/
			// add element to merkel tree
			//			char* out_buff = (char*)hashBlock;
			//			uint256 output(out_buff);
			uint512 hashBlock;
			ablake2b_state ctx;
			ablake2b_init(&ctx, ARGON2_PREHASH_DIGEST_LENGTH);
			ablake2b_update(&ctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
			ablake2b_final(&ctx, (unsigned char*)&hashBlock, ARGON2_PREHASH_DIGEST_LENGTH);

			leaves.push_back(hashBlock.trim256());


		}

		//		mt_hash_t resultMerkleRoot;
		int ret;
		//		ret = mt_get_root(mt, resultMerkleRoot);

		mtree = merkletree(leaves);

		//	leaves.clear();
		resultMerkleRoot = mtree.root();
	}

	return mtree;

}
//
void mtp_hash(char* output, const char* input, unsigned int d,uint32_t TheNonce) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx_from_mtp(&context, &instance);
//    mtp_prover(TheNonce, &instance, d, output);
//    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));

}