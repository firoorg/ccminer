#include "merkle-tree.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
//#include "blake2/blake2.h"
#include "../argon2ref/blake2.h"

std::ostream& operator<<(std::ostream& os, const MerkleTree::Buffer& buffer)
{
    for (   MerkleTree::Buffer::const_iterator it = buffer.begin();
            it != buffer.end();
            ++it) {
        os << std::hex << std::setw(2) << std::setfill('0') << *it;
    }
    return os;
}

MerkleTree::MerkleTree(uint8_t * elements, bool preserveOrder)
    : preserveOrder_(preserveOrder) /*, elements_(elements)*/
{

	elements_ = new uint8_t[sizeof(elements)];
	elements_ = elements;
	mem.push_back(elements_);

    getLayers();

}

MerkleTree::MerkleTree()
{
}
MerkleTree::~MerkleTree()
{



}
void MerkleTree::Destructor()
{

	uint32_t memsize = mem.size();
	for (int i = memsize-1; i>=1; i--) { // element 0 is.... aaahh !!!
//		free(this->mem[i]);
		delete[] mem[i];
		mem.pop_back(); 
	};
	delete[] this;
//	mem.clear();
//	mem.shrink_to_fit();

}

MerkleTree::Buffer MerkleTree::hash(const Buffer& data)
{
    ablake2b_state state;
    ablake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
  //  printf("%x %x %x %x\n",state.t[0],state.t[1],state.f[0],state.f[1]);
    for (Buffer::const_iterator it = data.begin(); it != data.end(); ++it) {
        ablake2b4rounds_update(&state, &(*it), sizeof(*it));
    }
    uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
    ablake2b4rounds_final(&state, digest, sizeof(digest));
    return Buffer(digest, digest + sizeof(digest));
}

void gen_layer(uint8_t* o, uint8_t* n, int size){
	for(int i=0;i<size;i++){
		ablake2b_state state;
	        ablake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
		ablake2b4rounds_update(&state, &o[32*i], 32);
		ablake2b4rounds_final(&state, &n[16*i], 16);
	}
}

MerkleTree::Buffer MerkleTree::combinedHash(const Buffer& first,
        const Buffer& second, bool preserveOrder)
{
    Buffer buffer;
//	if(first > second)
//		printf("%x > %x\n", first[0],second[0]);
    if (preserveOrder || (first > second)) {
        std::copy(first.begin(), first.end(), std::back_inserter(buffer));
        std::copy(second.begin(), second.end(), std::back_inserter(buffer));
    } else {
        std::copy(second.begin(), second.end(), std::back_inserter(buffer));
        std::copy(first.begin(), first.end(), std::back_inserter(buffer));
    }
//    printf("buf %lx\n",buffer[0]);

        Buffer x = hash(buffer);

//	for(int i=0;i<32;i++)
//		printf("%x ",x[i]);
//	printf("%d \n", preserveOrder);
//    for(;;);
    return hash(buffer);
}
/*
MerkleTree::Buffer MerkleTree::merkleRoot(const Elements& elements,
        bool preserveOrder)
{
    return MerkleTree(elements, preserveOrder).getRoot();
}
*/

/*
MerkleTree::Elements MerkleTree::getProof(const Buffer& element) const
{
    bool found = false;
    size_t index;
    for (size_t i = 0; (i < elements_.size()) && !found; ++i) {
        if (elements_[i] == element) {
		printf("Found ele %d\n",i);
            found = true;
            index = i;
        }
    }
	printf("x\n");
    if (!found) {
        throw std::runtime_error("Element not found");
    }
    return getProof(index);
}
*/
/*
std::string MerkleTree::getProofHex(const Buffer& element) const
{
    return elementsToHex(getProof(element));
}
*/
MerkleTree::Elements MerkleTree::getProofOrdered(const Buffer& element,
        size_t index) const
{
    if (index == 0) {
        throw std::runtime_error("Index is zero");
    }
    index--;
/*
    if ((index >= elements_.size()) || (elements_[index] != element)) {
        throw std::runtime_error("Index does not point to element");
    }*/
    return getProof(index);
}

std::string MerkleTree::getProofOrderedHex(const Buffer& element,
        size_t index) const
{
    return elementsToHex(getProofOrdered(element, index));
}




bool MerkleTree::checkProof(const Elements& proof, const Buffer& root,
        const Buffer& element)
{
    Buffer tempHash = element;
    for (   Elements::const_iterator it = proof.begin();
            it != proof.end();
            ++it) {
        tempHash = combinedHash(tempHash, *it, false);
    }
    return tempHash == root;
}

// Fabrice: This function seems buggy to me, rewrote it below
#if 0
bool MerkleTree::checkProofOrdered(const Elements& proof,
        const Buffer& root, const Buffer& element, size_t index)
{
    Buffer tempHash = element;
    for (size_t i = 0; i < proof.size(); ++i) {
        size_t remaining = proof.size() - i;

        // We don't assume that the tree is padded to a power of 2. If the
        // index is odd, then the proof starts with a hash at a higher layer,
        // so we have to adjust the index to be the index at that layer.
        while ((remaining > 0) && (index & 1) && (index > (1u << remaining))) {
            index = index / 2;
        }

        if (index & 1) {
            tempHash = combinedHash(tempHash, proof[i], true);
        } else {
            tempHash = combinedHash(proof[i], tempHash, true);
        }
        index = index / 2;
    }
    return tempHash == root;
}
#endif

bool MerkleTree::checkProofOrdered(const Elements& proof,
        const Buffer& root, const Buffer& element, size_t index)
{
    --index; // `index` argument starts at 1
    Buffer tempHash = element;
    for (size_t i = 0; i < proof.size(); ++i) {
        size_t remaining = proof.size() - i;

        // We don't assume that the tree is padded to a power of 2. If the
        // index is even and the last one of the layer, then the proof starts
        // with a hash at a higher layer, so we have to adjust the index to be
        // the index at that layer.
        while (((index & 1) == 0) && (index >= (1u << remaining))) {
            index = index / 2;
        }

        if (index & 1) {
            tempHash = combinedHash(proof[i], tempHash, true);
        } else {
            tempHash = combinedHash(tempHash, proof[i], true);
        }
        index = index / 2;
    }
    return tempHash == root;
}

void MerkleTree::getLayers()
{

	while (mem.size() < 23){
		getNextLayer();
	}

//for(;;);
/*
    layers_.clear();

    // The first layer is the elements themselves
    layers_.push_back(elements_);

    if (elements_.empty()) {
        return; // nothing left to do
    }

    // For subsequent layers, combine each pair of hashes in the previous
    // layer to build the current layer. Repeat until the current layer has
    // only one hash (this will be the root of the tree).
    while (layers_.back().size() > 1) {
        getNextLayer();
    }*/
}

void MerkleTree::getNextLayer()
{

uint8_t *prev_mem= mem.back();

int size=1024*1024*4*16;
for(int i=0;i<mem.size();i++)
	size/=2;
//printf("size %d %d %d\n",size, mem.size(), 1024*1024*4*16);
//uint8_t *new_mem=(uint8_t *)malloc(size);
	uint8_t *new_mem = new uint8_t[size];
gen_layer(prev_mem, new_mem, size/16);
mem.push_back(new_mem);


//for(;;);
/*
    const Elements& previous_layer = layers_.back();

    // Create a new empty layer
    layers_.push_back(Elements());
    Elements& current_layer = layers_.back();

    // For each pair of elements in the previous layer
    // NB: If there is an odd number of elements, we ignore the last one for now
    for (size_t i = 0; i < (previous_layer.size() / 2); ++i) {
        current_layer.push_back(combinedHash(previous_layer[2*i],
                    previous_layer[2*i + 1], preserveOrder_));
    }

//	printf("size %d %d\n",sizeof(current_layer.back()), sizeof(current_layer));
//for(;;);
    // If there is an odd one out at the end, process it
    // NB: It's on its own, so we don't combine it with anything
    if (previous_layer.size() & 1) {
        current_layer.push_back(previous_layer.back());
    }*/
}

MerkleTree::Elements MerkleTree::getProof(size_t index) const
{
    Elements proof;
/*
    for (   Layers::const_iterator it = layers_.begin();
            it != layers_.end();
            ++it) {
        Buffer pair;
        if (getPair(*it, index, pair)) {
            proof.push_back(pair);
        }
        index = index / 2; // point to correct hash in next layer
    } // for each layer
*/
	for(int i=0;i<mem.size();i++){
		Buffer pair;
		if (getPair2(mem, i, index, pair)) {
            proof.push_back(pair);
	//	printf("proof %d %d\n",index,i);
	//	for(int i=0;i<16;i++)printf("%x ",pair[i]);
	//	printf("\n");
	        index = index / 2; // point to correct hash in next layer

//		for(;;);
        }
	}
    return proof;
}
/*
bool MerkleTree::getPair(const Elements& layer, size_t index, Buffer& pair)
{
    size_t pairIndex;
    if (index & 1) {
        pairIndex = index - 1;
    } else {
        pairIndex = index + 1;
    }
    if (pairIndex >= layer.size()) {
        return false;
    }
    pair = layer[pairIndex];
    return true;
}*/

size_t get_chunk_size(size_t index){
size_t  size=1024*1024*4*16;
for(int i=0;i<index;i++)
        size/=2;
size/=16;
return size;
}

bool MerkleTree::getPair2(std::vector<uint8_t*> m, size_t chunk_index, size_t index, Buffer& pair)
{
    size_t pairIndex;
    if (index & 1) {
        pairIndex = index - 1;
    } else {
        pairIndex = index + 1;
    }
    if (pairIndex >= get_chunk_size(chunk_index)) {
        return false;
    }
//	printf("layer %d size %d addr %lx, ele %d\n",chunk_index,get_chunk_size(chunk_index), m[chunk_index], pairIndex);
    pair = MerkleTree::Buffer(&m[chunk_index][16*pairIndex], &m[chunk_index][16*pairIndex] + MERKLE_TREE_ELEMENT_SIZE_B);
//    pair = layer[pairIndex];
    return true;
}

void  MerkleTree::elementsToFormatHex(const Elements& elements, char* TheChar)
{

	int TheIt = 0;
	for (MerkleTree::Elements::const_iterator it = elements.begin();
		it != elements.end();
		++it) {
		std::vector<uint8_t> Truc = *it;
		for (int i = 0; i< Truc.size(); i++) {
			unsigned char TheUchar = Truc[i];
			sprintf(&TheChar[2 * TheIt], "%02x", TheUchar);
//			printf(" %02x ", TheUchar);
			TheIt++;
		}
	}
}

std::string MerkleTree::elementsToHex(const Elements& elements)
{
	std::ostringstream oss;
	oss << "0x";
	for (Elements::const_iterator it = elements.begin();
		it != elements.end();
		++it) {
		oss << *it;
	}
	return oss.str();
}

