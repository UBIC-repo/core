
#ifndef TX_CHAIN_H
#define TX_CHAIN_H

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include "Block/Block.h"

class Chain {
private:
    uint32_t bestBlockHeight = 0;
    std::vector<BlockHeader> bestBlocks; // Blocks that are on the top of the chain
public:
    static std::mutex connectBlockMutex;
    static Chain& Instance(){
        static Chain instance;
        return instance;
    }
    void setBlockHashAndHeightMap(uint64_t position, std::vector<unsigned char> headerHash);
    bool disconnectBlock(std::vector<unsigned char> blockHeaderHash);
    bool connectBlock(Block* block);
    bool connectBlock(Block* block, bool isRecursion);
    uint32_t getBlockHeight(std::vector<unsigned char> blockHeaderHash);
    BlockHeader* getBlockHeader(std::vector<unsigned char> blockHeaderHash);
    BlockHeader* getBlockHeader(uint64_t height);
    bool doesBlockExist(uint64_t height);
    bool doesBlockExist(std::vector<unsigned char> blockHeaderHash);
    uint32_t getCurrentBlockchainHeight();
    void setCurrentBlockchainHeight(uint32_t bestHeight);
    void setBestBlockHeaders(std::vector<BlockHeader> bestBlocks);
    std::vector<BlockHeader> getBestBlockHeaders();
    BlockHeader* getBestBlockHeader();
    void insertBlockHeader(BlockHeader blockHeader);
};


#endif //TX_CHAIN_H
