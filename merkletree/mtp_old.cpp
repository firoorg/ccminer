//
// Created by aizen on 4/9/17.
//

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




int mtp_prover(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, char* output) {
    //internal_kat(instance, r); /* Print all memory blocks */
    printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
    // Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory
    if (instance != NULL) {
        printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
        mt_t *mt = mt_create();
		 
        for (int i = 0; i < instance->memory_blocks; ++i) {
            block blockhash;
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            copy_block(&blockhash, &instance->memory[i]);
            store_block(&blockhash_bytes, &blockhash);
            // hash each block with sha256
            SHA256Context ctx;
            SHA256Context *pctx = &ctx;
            uint8_t hashBlock[32];
            int ret;
            ret = SHA256Reset(pctx);
            if (shaSuccess != ret) {
                return ret;
            }
            ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
            if (shaSuccess != ret) {
                return ret;
            }
            ret = SHA256Result(pctx, (uint8_t *) hashBlock);
            if (shaSuccess != ret) {
                return ret;
            }
            // add element to merkel tree
            mt_add(mt, hashBlock, HASH_LENGTH);

            // add element to blockchain header
            //memcpy(pblock->elementsInMerkleRoot[i], hashBlock, sizeof(uint8_t) * 32);

if (i== (instance->memory_blocks-1)) {
printf("i== %d element tot %d\n",i,mt->elems);

		printf("last hashBlock %08x %08x %08x %08x %08x %08x %08x %08x \n",
		((uint32_t*)hashBlock)[0], ((uint32_t*)hashBlock)[1], ((uint32_t*)hashBlock)[2], ((uint32_t*)hashBlock)[3],
		((uint32_t*)hashBlock)[4], ((uint32_t*)hashBlock)[5], ((uint32_t*)hashBlock)[6], ((uint32_t*)hashBlock)[7]
		);
}

        }

		while (true) {        
//            printf("Step 3 : Select nonce N \n");
//            pblock->nNonce += 1;
			TheNonce += 1;
//			if ((TheNonce & 0xff)==0xff) return 0;
            uint8_t Y[L + 1][32];
            memset(&Y[0], 0, sizeof(Y));

//            printf("Step 4 : Y0 = H(resultMerkelRoot, N) \n");
            mt_hash_t resultMerkleRoot;
            SHA256Context ctx;
            SHA256Context *pctx = &ctx;

            int ret;

//            printf("Step 4.1 : resultMerkleRoot \n");
            ret = mt_get_root(mt, resultMerkleRoot);
/*
            printf("Step 4.1 : resultMerkleRoot = 0x ");
            for (int i = 0; i < 8; i++) {
               printf(" %08x ", ((uint32_t*)resultMerkleRoot)[i]);
            }
            printf("\n");
*/
            if (MT_SUCCESS != ret) {
               return ret;
            }

 //           printf("Step 4.2 : SHA256Reset \n");
            ret = SHA256Reset(pctx);
            if (shaSuccess != ret) {
               return ret;
            }

//            printf("Step 4.3 : SHA256Input resultMerkleRoot\n");
            ret = SHA256Input(pctx, resultMerkleRoot, HASH_LENGTH);
            if (shaSuccess != ret) {
               return ret;
            }

            uint8_t nNonce[4];
			((uint32_t*)nNonce)[0]=TheNonce;
//            memcpy(nNonce, (uint8_t * ) & TheNonce, sizeof(nNonce));
			
            printf("Step 4.4 : SHA256Input nNonce %02x %02x  %02x %02x TheNonce %08x\n",nNonce[0],nNonce[1], nNonce[2], nNonce[3],TheNonce);
            ret = SHA256Input(pctx, nNonce, 4);
            if (shaSuccess != ret) {
               return ret;
            }

//            printf("Step 4.5 : SHA256Result\n");
            ret = SHA256Result(pctx, (uint8_t *) Y[0]);
            if (shaSuccess != ret) {
               return ret;
            }
			// test
//            printf("Step 5 : For 1 <= j <= L \n");
            //I(j) = Y(j - 1) mod T;
            //Y(j) = H(Y(j - 1), X[I(j)])
            //block_with_offset blockhashInBlockchain[140];
            bool init_blocks = false;
            bool unmatch_block = false;
            for (uint8_t j = 1; j <= L; j++) {
				uint32_t ij = ((uint32_t*)(Y[j-1]))[0] % (2*1024*1024); //(instance->context_ptr->m_cost);

//                uint32_t ij = *Y[j - 1] % 2048;
//				printf("ij = %08x\n",ij);
/*
printf("Yloc CPU %08x %08x %08x %08X %08x %08x %08x %08X ",
((uint32_t*)Y[j-1])[0], ((uint32_t*)Y[j - 1])[1], ((uint32_t*)Y[j - 1])[2], ((uint32_t*)Y[j - 1])[3], 
((uint32_t*)Y[j - 1])[4], ((uint32_t*)Y[j - 1])[5], ((uint32_t*)Y[j - 1])[6], ((uint32_t*)Y[j - 1])[7]
);
printf("CPU localIndex %d %08x Calculated %08x\n",ij,ij, ((uint32_t*)Y[j - 1])[0]%2048);
*/
                if (ij == 0 || ij == 1) {
                    init_blocks = true;
                    break;
                }

                block X_IJ;
	
                __m128i state_test[64];
                memset(state_test, 0, sizeof(state_test));

                memcpy(state_test, &instance->memory[instance->memory[ij].prev_block].v, ARGON2_BLOCK_SIZE);


                fill_block(state_test, &instance->memory[instance->memory[ij].ref_block], &X_IJ, 0);
//printf("cpu X_IJ %08x %08x %08x %08x \n",((uint32_t*)X_IJ.v)[0], ((uint32_t*)X_IJ.v)[1], ((uint32_t*)X_IJ.v)[2], ((uint32_t*)X_IJ.v)[3]);
                X_IJ.prev_block = instance->memory[ij].prev_block;
                X_IJ.ref_block = instance->memory[ij].ref_block;


//				printf(" ref_block %llx prev_block %llx\n", X_IJ.ref_block, X_IJ.prev_block);

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

                store_block(&blockhash_bytes, &blockhash);
                ret = SHA256Reset(pctx);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Input(pctx, (uint8_t *) Y[j - 1], HASH_LENGTH);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
                if (shaSuccess != ret) {
                   return ret;
                }
                ret = SHA256Result(pctx, (uint8_t *) Y[j]);
                if (shaSuccess != ret) {
                   return ret;
                }
            }
//			printf("init_blocks %d unmatch_block %d\n",init_blocks,unmatch_block);
/*
			printf("****************************************************Test hash: ");

			char hex_tmp[64];
			int n;
			for (n = 0; n < 8; n++) {
				printf(" %08x ", ((uint32_t*)Y[L])[n]);
			}
			printf("\n");
*/
            if (init_blocks) {
//                printf("Step 5.1 : init_blocks \n");
                continue;
            }

            if (unmatch_block) {
//                printf("Step 5.2 : unmatch_block \n");
                continue;
            }

            //unsigned int d = d_mtp;

//            printf("Current nBits: %s\n", CBigNum().SetCompact(pblock->nBits).getuint256().GetHex().c_str());
//            printf("****************************************************Current hash: Nonce=%08x\n",TheNonce);

            char hex_tmp[64];
            
            for (int n = 0; n < 8; n++) {
//                printf(" %08x ", ((uint32_t*)Y[L])[n]);
//                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
            }
//			printf("\n");
			for (int n = 0; n < 32; n++) {
//				printf(" %02x ", Y[L][n]);
                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
			}
//            printf("\n");

//            printf("Step 6 : If Y(L) had d trailing zeros, then (resultMerkelroot, N, Y(L)) \n");
            //uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            //printf("*** hashTarget: %d %s ***\n", hashTarget, hashTarget.GetHex().c_str());
            if (trailing_zeros(hex_tmp) < d) {
                continue;
            } else {
                // Found a solution
				printf("****************************************************Current hash: Nonce=%08x\n", TheNonce);
                printf("Found a solution. Hash:");
                for (int n = 0; n < 32; n++) {
                   printf("%02x", Y[L][n]);
                }
                printf("\n");
				for (int n = 0; n < 8; n++) {
					printf(" %08x ", ((uint32_t*)Y[L])[n]);
					//                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
				}
				printf("\n");
                // TODO: copy hash to output
                memcpy(output, Y[L], 32);
                return 0;
                //printf("O-2\n");
            }
            //printf("O-3\n");
		
        }
        //printf("O-4\n");
    }
    //printf("O-5\n");
    return 1;
}

int mtp_solver(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, char* output, unsigned char *resultMerkleRoot) {

	if (instance != NULL) {
 
			uint8_t Y[L + 1][32];
			memset(&Y[0], 0, sizeof(Y));
 
			SHA256Context ctx;
			SHA256Context *pctx = &ctx;

			int ret;
 
			ret = SHA256Reset(pctx);
			if (shaSuccess != ret) {
				return ret;
			}

 
			ret = SHA256Input(pctx, resultMerkleRoot, HASH_LENGTH);
			if (shaSuccess != ret) {
				return ret;
			}

			uint8_t nNonce[4];
			((uint32_t*)nNonce)[0] = TheNonce;

			ret = SHA256Input(pctx, nNonce, 4);
			if (shaSuccess != ret) {
				return ret;
			}

			ret = SHA256Result(pctx, (uint8_t *)Y[0]);
			if (shaSuccess != ret) {
				return ret;
			}
 
			bool init_blocks = false;
			bool unmatch_block = false;
			for (uint8_t j = 1; j <= L; j++) {
				uint32_t ij = ((uint32_t*)(Y[j - 1]))[0] % (instance->context_ptr->m_cost);
 
				if (ij == 0 || ij == 1) {
					init_blocks = true;
					break;
				}

				block X_IJ;

				__m128i state_test[64];
				memset(state_test, 0, sizeof(state_test));

				memcpy(state_test, &instance->memory[instance->memory[ij].prev_block & 0xffffffff].v, ARGON2_BLOCK_SIZE);

				fill_block(state_test, &instance->memory[instance->memory[ij].ref_block], &X_IJ, 0);

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

				store_block(&blockhash_bytes, &blockhash);
				ret = SHA256Reset(pctx);
				if (shaSuccess != ret) {
					return ret;
				}
				ret = SHA256Input(pctx, (uint8_t *)Y[j - 1], HASH_LENGTH);
				if (shaSuccess != ret) {
					return ret;
				}
				ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
				if (shaSuccess != ret) {
					return ret;
				}
				ret = SHA256Result(pctx, (uint8_t *)Y[j]);
				if (shaSuccess != ret) {
					return ret;
				}
			}

			if (init_blocks) {
				//                printf("Step 5.1 : init_blocks \n");
				return 0;
			}

			if (unmatch_block) {
				//                printf("Step 5.2 : unmatch_block \n");
				return 0;
			}

			char hex_tmp[64];

			for (int n = 0; n < 32; n++) {
				//				printf(" %02x ", Y[L][n]);
				sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
			}

			if (trailing_zeros(hex_tmp) < d) {
				return 0;
			}
			else {
				// Found a solution
				printf("****************************************************Current hash: Nonce=%08x\n", TheNonce);
				printf("Found a solution. Hash:");
				for (int n = 0; n < 32; n++) {
					printf("%02x", Y[L][n]);
				}
				printf("\n");
				for (int n = 0; n < 8; n++) {
					printf(" %08x ", ((uint32_t*)Y[L])[n]);
					//                sprintf(&hex_tmp[n * 2], "%02x", Y[L][n]);
				}
				printf("\n");
				// TODO: copy hash to output
				memcpy(output, Y[L], 32);
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

int mtp_init(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, unsigned char *resultMerkleRoot) {
	//internal_kat(instance, r); /* Print all memory blocks */
	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
	// Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory
	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
		mt_t *mt = mt_create();

		for (int i = 0; i < instance->memory_blocks; ++i) {
			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance->memory[i]);
			store_block(&blockhash_bytes, &blockhash);
			// hash each block with sha256
			SHA256Context ctx;
			SHA256Context *pctx = &ctx;
			uint8_t hashBlock[32];
			int ret;
			ret = SHA256Reset(pctx);
			if (shaSuccess != ret) {
				return ret;
			}
			ret = SHA256Input(pctx, blockhash_bytes, ARGON2_BLOCK_SIZE);
			if (shaSuccess != ret) {
				return ret;
			}
			ret = SHA256Result(pctx, (uint8_t *)hashBlock);
			if (shaSuccess != ret) {
				return ret;
			}
			// add element to merkel tree
			mt_add(mt, hashBlock, HASH_LENGTH);

			// add element to blockchain header
			//memcpy(pblock->elementsInMerkleRoot[i], hashBlock, sizeof(uint8_t) * 32);

			if (i == (instance->memory_blocks - 1)) {
				printf("i== %d element tot %d\n", i, mt->elems);

				printf("last hashBlock %08x %08x %08x %08x %08x %08x %08x %08x \n",
					((uint32_t*)hashBlock)[0], ((uint32_t*)hashBlock)[1], ((uint32_t*)hashBlock)[2], ((uint32_t*)hashBlock)[3],
					((uint32_t*)hashBlock)[4], ((uint32_t*)hashBlock)[5], ((uint32_t*)hashBlock)[6], ((uint32_t*)hashBlock)[7]
				);
			}

		}
		//		mt_hash_t resultMerkleRoot;
		int ret;
		ret = mt_get_root(mt, resultMerkleRoot);


	}
		return 1;

}
//
void mtp_hash(char* output, const char* input, unsigned int d,uint32_t TheNonce) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx_from_mtp(&context, &instance);
    mtp_prover(TheNonce, &instance, d, output);
    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));
}