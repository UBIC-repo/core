
#ifndef TX_BLOCKCACHE_H
#define TX_BLOCKCACHE_H

#include <cstdint>
#include "../Block.h"
#include "../Chain.h"
#include "../Tools/Log.h"
#include "BanList.h"

typedef std::string ip_t;
typedef std::vector<unsigned char> hash_t;

class BlockCache {
private:
    std::mutex cacheMutex;
    std::mutex appendBlockMutex;
    std::mutex blockHeightAskedMapMutex;
    std::mutex blockHashAskedMapMutex;
    std::map<hash_t, std::pair<ip_t, Block> > cache;
    std::map<ip_t, std::vector<uint32_t> > blockHeightAskedMap; // ip, height list
    std::map<ip_t, hash_t> blockHashAskedMap;

    // this maps block header hashes to an ip and is used to ban a node when it turns out later that the block was invalid
    std::map<hash_t, ip_t> receivedBlockHistory;

    void tryToAppendBlocksToChain() {
        BanList& banList = BanList::Instance();
        Chain &chain = Chain::Instance();
        uint64_t currentBlockchainHeight = chain.getCurrentBlockchainHeight();
        
        bool continueAppending = true;
        while(continueAppending) {
            continueAppending = false;
            for (auto blockIt = cache.begin(); blockIt != cache.end();) {

                Block* block = &blockIt->second.second;
                BlockHeader* blockHeader = chain.getBlockHeader(block->getHeader()->getPreviousHeaderHash());
                if (block->getHeader()->getBlockHeight() == 1
                    || blockHeader != nullptr) {
                    delete blockHeader;
                    if (chain.doesBlockExist(block->getHeader()->getHeaderHash())
                        && chain.doesBlockExist(block->getHeader()->getBlockHeight())) {
                        Log(LOG_LEVEL_INFO) << "remove block:" << block->getHeader()->getHeaderHash()
                                            << " from cache because it is already in our chain";
                        cacheMutex.lock();                        
                        blockIt = cache.erase(blockIt);
                        cacheMutex.unlock();
                    } else if (chain.connectBlock(block)) {
                        Log(LOG_LEVEL_INFO) << "remove block:" << block->getHeader()->getHeaderHash()
                                            << " from cache";

                        continueAppending = true; // continue try appending, may be after connecting this block another from the cache can be connected to
                        cacheMutex.lock();                        
                        blockIt = cache.erase(blockIt);
                        cacheMutex.unlock();
                    } else {
                        // Failed to connect block
                        Log(LOG_LEVEL_INFO) << "remove invalid block:" << block->getHeader()->getHeaderHash()
                                            << " from cache and add ban";
                        banList.appendBan(blockIt->second.first, BAN_INC_FOR_INVALID_BLOCK);
                        cacheMutex.lock();                        
                        blockIt = cache.erase(blockIt);
                        cacheMutex.unlock();
                    }
                } else {
                    delete blockHeader;
                    blockIt++;
                }
            }
        }

        Log(LOG_LEVEL_INFO) << "tryToAppendBlocksToChain() done";
    }
public:

    static BlockCache& Instance(){
        static BlockCache instance;
        return instance;
    }

    void appendHistory(ip_t ip, hash_t hash) {
        this->receivedBlockHistory.insert(std::make_pair(hash, ip));
    }

    ip_t getIpForBlock(hash_t hash) {
        auto ipIt = this->receivedBlockHistory.find(hash);
        if(ipIt != this->receivedBlockHistory.end()) {
            return ipIt->second;
        }

        return "";
    }

    void appendBlock(PeerInterfacePtr from, Block* block) {
        appendBlockMutex.lock();
        std::map<hash_t, std::pair<ip_t, Block> >::iterator cacheIt = this->cache.find(block->getHeader()->getHeaderHash());
        if(cacheIt == this->cache.end()) {
            this->cache.insert(std::make_pair(block->getHeader()->getHeaderHash(), std::make_pair(from->getIp(), *block)));
        }

        // remove entry from blockHeightAskedMap
        blockHeightAskedMapMutex.lock();
        auto found = this->blockHeightAskedMap.find(from->getIp());
        if(found != this->blockHeightAskedMap.end()) {
            for(auto it = found->second.begin(); it != found->second.end();) {
                if(*it == block->getHeader()->getBlockHeight()) {
                    Log(LOG_LEVEL_INFO) << "removed entry " << *it << " from blockHeightAskedMap";
                    it = found->second.erase(it);
                    if(found->second.empty()) {
                        Log(LOG_LEVEL_INFO) << "removed all entries for " << from->getIp() << " from blockHeightAskedMap";
                        this->blockHeightAskedMap.erase(found);
                        break;
                    }
                } else {
                    it++;
                }
            }
        }
        blockHeightAskedMapMutex.unlock();

        // remove entry from blockHashAskedMap
        blockHashAskedMapMutex.lock();
        auto found2 = this->blockHashAskedMap.find(from->getIp());
        if(found2 != this->blockHashAskedMap.end()) {
            if(found2->second == block->getHeader()->getHeaderHash()) {
                Log(LOG_LEVEL_INFO) << "removed entry from blockHashAskedMap";
                this->blockHashAskedMap.erase(found2);
            }
        }
        blockHashAskedMapMutex.unlock();

        // insert entry to history
        this->appendHistory(from->getIp(), block->getHeader()->getHeaderHash());

        this->tryToAppendBlocksToChain();
        appendBlockMutex.unlock();
    }

    std::vector<hash_t> missingBlockHashList() {
        std::vector<hash_t> missing;
        cacheMutex.lock();
        for(auto blockIt: cache) {
            auto found = cache.find(blockIt.second.second.getHeader()->getPreviousHeaderHash());
            if(found == cache.end()) {
                missing.emplace_back(blockIt.second.second.getHeader()->getPreviousHeaderHash());
            }
        }
        cacheMutex.unlock();

        Log(LOG_LEVEL_INFO) << "missingBlockHashList size: " << (uint64_t)missing.size();

        return missing;
    }

    bool isBlockInCache(uint64_t height) {
        cacheMutex.lock();
        if(this->cache.empty()) {
            cacheMutex.unlock();
            return false;
        }
        for(auto& block : this->cache) {
            if(block.second.second.getHeader()->getBlockHeight() == height) {
                cacheMutex.unlock();
                return true;
            }
        }
        cacheMutex.unlock();
        return false;
    }

    bool isBlockInCache(hash_t headerHash) {
        cacheMutex.lock();
        auto found = this->cache.find(headerHash);
        cacheMutex.unlock();
        return found != this->cache.end();
    }

    bool hasWork(ip_t ip) {
        blockHeightAskedMapMutex.lock();
        blockHashAskedMapMutex.lock();
        bool hasWork =  this->blockHeightAskedMap.find(ip) != this->blockHeightAskedMap.end()
               || this->blockHashAskedMap.find(ip) != this->blockHashAskedMap.end();
        blockHeightAskedMapMutex.unlock();
        blockHashAskedMapMutex.unlock();
        return hasWork;
    }

    bool verifyAskedFor(ip_t ip, hash_t headerHash, uint32_t blockHeight) {
        blockHeightAskedMapMutex.lock();
        auto foundHeight = this->blockHeightAskedMap.find(ip);
        if(foundHeight != this->blockHeightAskedMap.end()) {
            for(uint32_t height : foundHeight->second) {
                if(height == blockHeight) {
                    blockHeightAskedMapMutex.unlock();
                    return true;
                }
            }
        }
        blockHeightAskedMapMutex.unlock();

        blockHashAskedMapMutex.lock();
        auto foundHash = this->blockHashAskedMap.find(ip);
        if(foundHash != this->blockHashAskedMap.end()) {
            if(foundHash->second == headerHash) {
                blockHashAskedMapMutex.unlock();
                return true;
            }
        }
        blockHashAskedMapMutex.unlock();
        return false;
    }

    void insertInBlockHeightAskedMap(ip_t ip, std::vector<uint32_t> blockHeight) {
        blockHeightAskedMapMutex.lock();
        this->blockHeightAskedMap.insert(std::make_pair(ip, blockHeight));
        blockHeightAskedMapMutex.unlock();
    }

    void insertInBlockHashAskedMap(ip_t ip, hash_t blockHash) {
        blockHashAskedMapMutex.lock();
        this->blockHashAskedMap.insert(std::make_pair(ip, blockHash));
        blockHashAskedMapMutex.unlock();
    }
};


#endif //TX_BLOCKCACHE_H
