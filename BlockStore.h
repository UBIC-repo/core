
#ifndef TX_BLOCKSTORE_H
#define TX_BLOCKSTORE_H

#include "Block.h"

class BlockStore {
public:
    static void insertBlock(Block* block);
    static Block* getBlock(std::vector<unsigned char> blockHeaderHash);
    static std::vector<unsigned char> getRawBlockVector(std::vector<unsigned char> blockHeaderHash);
};

class BlockIndex {
private:
    std::vector<unsigned char> blockDatPath;
    uint64_t startPosition;
    uint64_t size;
public:
    std::vector<unsigned char> getBlockDatPath() {
        return blockDatPath;
    }

    void setBlockDatPath(std::vector<unsigned char> &blockDatPath) {
        BlockIndex::blockDatPath = blockDatPath;
    }

    uint64_t getStartPosition() {
        return startPosition;
    }

    void setStartPosition(uint64_t startPosition) {
        BlockIndex::startPosition = startPosition;
    }

    uint64_t getSize() {
        return size;
    }

    void setSize(uint64_t size) {
        BlockIndex::size = size;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockDatPath);
        READWRITE(startPosition);
        READWRITE(size);
    }
};


#endif //TX_BLOCKSTORE_H
