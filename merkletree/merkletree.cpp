#include "merkletree.hpp"
//#include "../argon2ref/blake2.h"
#include <cstdlib>

// buff 

char* serializeMTP(vector<ProofNode>& proof) // Writes the given OBJECT data to the given file name.
{
    char* result = (char*)std::malloc(proof.size() * NODE_LENGTH + 1);
    result[proof.size() * NODE_LENGTH] = 0;
	for (int i = 0; i < proof.size(); i++) {
        memcpy(result+NODE_LENGTH*i+1,proof[i].hash.GetHex().c_str(),SHA256_LENGTH);
        result[NODE_LENGTH*i] = proof[i].isRight? '1':'0';
	}
	return result;
};

vector<ProofNode> deserializeMTP(const char* strdata) // Reads the given file and assigns the data to the given OBJECT.
{
	size_t datalen = strlen(strdata);
    vector<ProofNode> proof(datalen / NODE_LENGTH);

    char *node = new char[SHA256_LENGTH + 1];
    node[SHA256_LENGTH] = 0;

    for (int i = 0; i < proof.size(); i++) {
        memcpy(node,strdata+NODE_LENGTH*i+1,SHA256_LENGTH);
        uint256 v_node(node);
        proof[i].hash = v_node;
        proof[i].isRight = strdata[NODE_LENGTH*i] != '0';
	}

	return proof;
};



// combin and hash by sha256

uint256 combine_old(uint256 leftData, uint256 rightData) {
	uint256 hash1;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &leftData, sizeof(uint256));
	SHA256_Update(&sha256, &rightData, sizeof(uint256));
	SHA256_Final((unsigned char*)&hash1, &sha256);

	uint256 hash2;
	SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
//	printf("hash = %s\n", hash2.GetHex().c_str());
	return hash2;
}

uint256 combine(uint256 leftData, uint256 rightData) {
	uint256 hash1;
	ablake2b_state BlakeHash;
	ablake2b_init(&BlakeHash, 16);
	ablake2b4rounds_update(&BlakeHash, &leftData, sizeof(uint256)/2);
	ablake2b4rounds_update(&BlakeHash, &rightData, sizeof(uint256)/2);
	ablake2b4rounds_final(&BlakeHash,(unsigned char*)&hash1, 16);

	uint256 hash2;
//	SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
	ablake2b_init(&BlakeHash, 16);
	ablake2b4rounds_update(&BlakeHash, &hash1, sizeof(uint256)/2);
	ablake2b4rounds_final(&BlakeHash, (unsigned char*)&hash2, 16);
	//	printf("hash = %s\n", hash2.GetHex().c_str());
	return hash2;
}

bool verifyProof(uint256 leaf, uint256 expectedMerkleRoot, vector<ProofNode> proofArr) {

    if (proofArr.size() == 0) {
		if (leaf != expectedMerkleRoot)
			return true;
		return false;
	}

	// the merkle root should be the parent of the last part
    uint256 actualMekleRoot = proofArr[proofArr.size() - 1].hash;

	if (actualMekleRoot != expectedMerkleRoot)
		return false;


    for (int pIdx = 0; pIdx < proofArr.size() - 1; pIdx++) {
        if (proofArr[pIdx].isRight){
            leaf = combine(leaf,proofArr[pIdx].hash);
        }else{
            leaf = combine(proofArr[pIdx].hash,leaf);
        }
	}
/*
	printf("prevParent = %s\n", prevParent.GetHex().c_str());
	printf("expectedMerkleRoot = %s\n", expectedMerkleRoot.GetHex().c_str());
*/
    if (leaf == expectedMerkleRoot) {
		return true;
	}
	else {
		return false;
	}

}

