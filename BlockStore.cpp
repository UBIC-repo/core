
#include "BlockStore.h"
#include "FS/FS.h"
#include "DB/DB.h"

void BlockStore::insertBlock(Block* block) {

    std::vector<unsigned char> blockDatPath = FS::getBlockDatPath();

    uint64_t bPosition = FS::getEofPosition(blockDatPath);
    FS::serializeToFile(blockDatPath, *block);
    uint64_t ePosition = FS::getEofPosition(blockDatPath);

    BlockIndex index;
    index.setBlockDatPath(blockDatPath);
    index.setStartPosition(bPosition);
    index.setSize(ePosition - bPosition);

    DB& db = DB::Instance();
    db.serializeToDb(DB_BLOCK_INDEX, block->getHeader()->getHeaderHash(), index);
}

Block* BlockStore::getBlock(std::vector<unsigned char> blockHeaderHash) {
    DB& db = DB::Instance();

    BlockIndex *index = new BlockIndex();
    db.deserializeFromDb(DB_BLOCK_INDEX, blockHeaderHash, *index);

    uint64_t nextPos;
    bool eof;

    Block* block = new Block();
    FS::deserializeFromFile(index->getBlockDatPath(), BLOCK_SIZE_MAX, index->getStartPosition(), *block, nextPos , eof);

    return block;
}

std::vector<unsigned char> BlockStore::getRawBlockVector(std::vector<unsigned char> blockHeaderHash) {
    DB& db = DB::Instance();

    BlockIndex *index = new BlockIndex();
    db.deserializeFromDb(DB_BLOCK_INDEX, blockHeaderHash, *index);

    return FS::readFile(index->getBlockDatPath(), index->getStartPosition(), index->getSize());
}
