
#include "Chain.h"
#include "BlockStore.h"
#include "Tools/Log.h"
#include "FS/FS.h"
#include "DB/DB.h"
#include "TxPool.h"
#include "Network/BanList.h"
#include "Network/BlockCache.h"
#include "App.h"
#include "Network/Network.h"

std::mutex Chain::connectBlockMutex;

void Chain::setBlockHashAndHeightMap(uint64_t position, std::vector<unsigned char> headerHash) {
    DB &db = DB::Instance();
    db.putInDB(DB_BLOCK_HEADERS, position, headerHash);
}

bool Chain::disconnectBlock(std::vector<unsigned char> blockHeaderHash) {
    TxPool& txPool = TxPool::Instance();
    Block* block = BlockStore::getBlock(blockHeaderHash);

    if(block == nullptr) {
        Log(LOG_LEVEL_ERROR) << "Cannot disconnect block:" << blockHeaderHash << " because block was not found in block store";
        return false;
    }

    bool success = BlockHelper::undoBlock(block);
    // put transactions from Block back into TxPool
    txPool.appendTransactionsFromBlock(block);
    return success;
}

bool Chain::connectBlock(Block* block) {
    return Chain::connectBlock(block, false);
}

bool Chain::connectBlock(Block* block, bool isRecursion) {

    App& app = App::Instance();
    if(app.getTerminateSignal()) {
        Log(LOG_LEVEL_INFO) << "cannot connect a new block, received terminate signal";
        return false;
    }

    if(!isRecursion) {
        connectBlockMutex.lock();
    }

    DB &db = DB::Instance();
    BlockHeader* header = block->getHeader();

    Log(LOG_LEVEL_INFO) << "attempting to add block with hash "
                        << header->getHeaderHash()
                        << "\n"
                        << " and height "
                        << "\n"
                        << header->getBlockHeight()
                        << " to the chain"
                        << "\n"
                        << "Payout:"
                        << header->getPayout()
                        << "\n"
                        << "PayoutRemainder:"
                        << header->getPayoutRemainder()
                        << "\n"
                        << "UbiReceiverCount:"
                        << header->getUbiReceiverCount()
                        << "\n"
                        << "transaction count:"
                        << (uint32_t)block->getTransactions().size();

    BlockHeader* previousHeader = getBlockHeader(header->getPreviousHeaderHash());
    if(previousHeader == nullptr) {
        if(header->getPreviousHeaderHash().empty()) {
            if(header->getBlockHeight() != 1) {
                Log(LOG_LEVEL_ERROR) << "Genesis block should be of height 1";
                connectBlockMutex.unlock();
                return false;
            }
            // genesis block
        } else {
            Log(LOG_LEVEL_ERROR) << "couldn't connect block " << header->getHeaderHash() << " to chain, previous block not found";
            connectBlockMutex.unlock();
            return false;
        }
    } else {
        if(header->getBlockHeight() != previousHeader->getBlockHeight() + 1) {
            Log(LOG_LEVEL_ERROR) << "previous blockheight is "
                                 << previousHeader->getBlockHeight()
                                 << " but expected to be "
                                 << header->getBlockHeight() - 1;
            connectBlockMutex.unlock();
            return false;
        }
    }

    BlockHeader* bestBlockHeader = this->getBestBlockHeader();

    if(this->bestBlockHeight >= header->getBlockHeight()) {

        // fork without consequences
        Log(LOG_LEVEL_INFO) << "Detected a fork, block: " << header->getHeaderHash() << " at height: " << header->getBlockHeight();

        //add block to chain
        BlockStore::insertBlock(block);
        db.serializeToDb(DB_BLOCK_HEADERS, header->getHeaderHash(), *header);

        // If block has the same height as the other highest block
        if(this->bestBlockHeight == header->getBlockHeight()) {
            this->bestBlocks.emplace_back(*header);
        }

        connectBlockMutex.unlock();
        return true;
    } else if(bestBlockHeader != nullptr && !block->getHeader()->getPreviousHeaderHash().empty()) {
        if (bestBlockHeader->getHeaderHash() != block->getHeader()->getPreviousHeaderHash()) {
            // fork with consequences
            // Need to solve the fork
            Log(LOG_LEVEL_INFO) << "Started trying to solve a fork";
            bool forkFailed = false;
            std::vector<std::vector<unsigned char> > toUndo;
            std::vector<std::vector<unsigned char> > toDo;

            std::vector<unsigned char> currentChainHeaderHash = bestBlockHeader->getHeaderHash();
            std::vector<unsigned char> newChainHeaderHash = block->getHeader()->getPreviousHeaderHash();
            std::vector<unsigned char> commonHeaderHash;

            bool foundCommonHeader = false;
            while (!foundCommonHeader) {
                Log(LOG_LEVEL_INFO) << "currentChainHeaderHash: " << currentChainHeaderHash;
                toUndo.emplace_back(currentChainHeaderHash);
                toDo.emplace_back(newChainHeaderHash);

                BlockHeader* currentChainHeader = this->getBlockHeader(currentChainHeaderHash);
                BlockHeader* newChainHeader = this->getBlockHeader(newChainHeaderHash);
                if(currentChainHeader == nullptr || newChainHeader == nullptr) {
                    Log(LOG_LEVEL_ERROR) << "Something went wrong, reverting fork";
                    forkFailed = true;
                    break;
                }
                currentChainHeaderHash = currentChainHeader->getPreviousHeaderHash();
                newChainHeaderHash = newChainHeader->getPreviousHeaderHash();
                delete newChainHeader;
                delete currentChainHeader;

                for(auto toDoHeaderHash : toDo) {
                    auto found = std::find(toUndo.begin(), toUndo.end(), toDoHeaderHash);
                    if (found != toUndo.end()) {
                        foundCommonHeader = true;
                        commonHeaderHash = *found;
                    }
                }
            }

            Log(LOG_LEVEL_INFO) << "Found common header:" << commonHeaderHash;

            // Undo common header as well as all previous headers
            bool reachedCommonHeader = false;
            for(std::vector<std::vector<unsigned char> >::iterator it = toDo.begin(); it != toDo.end();) {
                if(*it == commonHeaderHash) {
                    reachedCommonHeader = true;
                }
                if(reachedCommonHeader) {
                    it = toDo.erase(it);
                } else {
                    it++;
                }
            }

            // for undo too
            reachedCommonHeader = false;
            for(std::vector<std::vector<unsigned char> >::iterator it = toUndo.begin(); it != toUndo.end();) {
                if(*it == commonHeaderHash) {
                    reachedCommonHeader = true;
                }
                if(reachedCommonHeader) {
                    it = toUndo.erase(it);
                } else {
                    it++;
                }
            }

            Log(LOG_LEVEL_INFO) << "Need to disconnect " << (uint64_t)toUndo.size() << " blocks";

            // disconnect all blocks until last common block
            for (std::vector<std::vector<unsigned char>>::iterator it = toUndo.begin(); it != toUndo.end(); it++) {
                Log(LOG_LEVEL_INFO) << "Disconnecting: " << *it;
                this->disconnectBlock(*it);
            }

            std::vector<BlockHeader> newBestBlockHeader;
            BlockHeader commonBlock = *this->getBlockHeader(commonHeaderHash);
            newBestBlockHeader.emplace_back(commonBlock);
            this->setBestBlockHeaders(newBestBlockHeader);
            this->bestBlockHeight = commonBlock.getBlockHeight();

            Log(LOG_LEVEL_INFO) << "Blocks are now disconnected";
            Log(LOG_LEVEL_INFO) << "Will apply " << (uint64_t)toDo.size() << " new blocks";

            std::vector<std::vector<unsigned char> > appliedTodos;

            BanList& banList = BanList::Instance();
            BlockCache& blockCache = BlockCache::Instance();

            // apply blocks from new best chain
            for (std::vector<std::vector<unsigned char>>::reverse_iterator it = toDo.rbegin();
                 it != toDo.rend(); it++) {
                Block *blockFromStore = BlockStore::getBlock(*it);
                if (BlockHelper::verifyBlock(blockFromStore)) {
                    if(this->connectBlock(blockFromStore, true)) {
                        appliedTodos.emplace_back(*it);
                    } else {
                        banList.appendBan(blockCache.getIpForBlock(*it), BAN_INC_INSTA_BAN);
                        forkFailed = true;
                    }
                } else {
                    banList.appendBan(blockCache.getIpForBlock(*it), BAN_INC_INSTA_BAN);
                    forkFailed = true;
                }
            }
            if(!forkFailed) {
                Log(LOG_LEVEL_INFO) << "New blocks applied, fork success";
            }

            // fork failed because it contains invalid block(s), rollback and delete this evil fork
            if (forkFailed) {
                Log(LOG_LEVEL_INFO) << "Fork failed, need to rollback!";

                // rollback all applied todos
                for (std::vector<std::vector<unsigned char>>::iterator it = appliedTodos.begin(); it != appliedTodos.end(); it++) {
                    Log(LOG_LEVEL_INFO) << "Rollback: " << *it;
                    this->disconnectBlock(*it);
                }

                // reapply all untodos
                for (std::vector<std::vector<unsigned char>>::reverse_iterator it = toUndo.rbegin(); it != toUndo.rend(); it++) {
                    Log(LOG_LEVEL_INFO) << "Connecting: " << *it;
                    Block *blockFromStore = BlockStore::getBlock(*it);
                    if (BlockHelper::verifyBlock(blockFromStore)) {
                        this->connectBlock(blockFromStore);
                    } else {
                        Log(LOG_LEVEL_CRITICAL_ERROR) << "Rollback failed after a bad fork";
                        // terminate app to avoid more damage
                        App& app = App::Instance();
                        app.terminate();
                        return false;
                    }
                }
            }
        }
    }

    //verify block
    if(!BlockHelper::verifyBlock(block)) {
        Log(LOG_LEVEL_ERROR) << "couldn't connect block " << header->getHeaderHash() << " to chain, verification failed";
        connectBlockMutex.unlock();
        return false;
    }

    //add block to chain
    BlockStore::insertBlock(block);
    db.serializeToDb(DB_BLOCK_HEADERS, header->getHeaderHash(), *header);

    // Apply blocks
    BlockHelper::applyBlock(block);

    //update best blocks
    this->bestBlockHeight = header->getBlockHeight();
    std::vector<BlockHeader> newBestBlocks = std::vector<BlockHeader>();
    newBestBlocks.emplace_back(*header);
    this->setBestBlockHeaders(newBestBlocks);
    db.putInDB(DB_BLOCK_HEADERS, header->getBlockHeight(), header->getHeaderHash());

    FS::clearFile(FS::getBestBlockHeadersPath());
    for(BlockHeader bestHeader: this->bestBlocks) {
        FS::serializeToFile(FS::getBestBlockHeadersPath(), bestHeader);
    }

    Log(LOG_LEVEL_INFO) << "added block with hash "
                        << header->getHeaderHash()
                        << " and height "
                        << header->getBlockHeight()
                        << " to the chain";

    connectBlockMutex.unlock();
    
    std::thread t1(&Network::broadCastNewBlockHeight, header->getBlockHeight(), header->getHeaderHash());
    t1.detach();

    return true;
}

uint32_t Chain::getBlockHeight(std::vector<unsigned char> blockHeaderHash) {
    BlockHeader* blockHeader = this->getBlockHeader(blockHeaderHash);

    if(blockHeader != nullptr) {
        uint32_t height = blockHeader->getBlockHeight();
        delete blockHeader;
        return height;
    }

    return 0;
}

BlockHeader* Chain::getBlockHeader(std::vector<unsigned char> blockHeaderHash) {

    if(blockHeaderHash.empty()) {
        return nullptr;
    }

    DB &db = DB::Instance();
    BlockHeader* blockHeader = new BlockHeader();

    if(db.deserializeFromDb(DB_BLOCK_HEADERS, blockHeaderHash, *blockHeader)) {
        return blockHeader;
    }

    return nullptr;
}

BlockHeader* Chain::getBlockHeader(uint64_t height) {
    DB &db = DB::Instance();

    std::vector<unsigned char> blockHeaderHash = db.getFromDB(DB_BLOCK_HEADERS, height);

    if(!blockHeaderHash.empty()) {
        return this->getBlockHeader(blockHeaderHash);
    }

    return nullptr;
}

bool Chain::doesBlockExist(uint64_t height) {
    DB &db = DB::Instance();

    std::vector<unsigned char> blockHeaderHash = db.getFromDB(DB_BLOCK_HEADERS, height);

    return !blockHeaderHash.empty();
}

bool Chain::doesBlockExist(std::vector<unsigned char> blockHeaderHash) {
    DB &db = DB::Instance();
    
    return db.isInDB(DB_BLOCK_HEADERS, blockHeaderHash);
}

uint32_t Chain::getCurrentBlockchainHeight() {
    return this->bestBlockHeight;
}

void Chain::setCurrentBlockchainHeight(uint32_t bestHeight) {
    this->bestBlockHeight = bestHeight;
}

void Chain::setBestBlockHeaders(std::vector<BlockHeader> newBestBlocks) {
    this->bestBlocks = newBestBlocks;
}

std::vector<BlockHeader> Chain::getBestBlockHeaders() {
    return this->bestBlocks;
}

BlockHeader* Chain::getBestBlockHeader() {
    if(this->bestBlocks.size() == 0) {
        return nullptr;
    }
    return &this->bestBlocks[0];
}

void Chain::insertBlockHeader(BlockHeader blockHeader) {
    DB &db = DB::Instance();
    db.serializeToDb(DB_BLOCK_HEADERS, blockHeader.getHeaderHash(), blockHeader);
}
