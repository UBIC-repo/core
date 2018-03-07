
#ifndef TX_NETWORK_H
#define TX_NETWORK_H

#include <vector>
#include "../Transaction/Transaction.h"
#include "../Block.h"

class Network {
private:
public:
    static bool synced;
    static bool isSyncing;
    static uint64_t lastPeerLookup;
    static Network& Instance(){
        static Network instance;
        return instance;
    }

    std::vector<std::string> getIpsFromGithub();
    void lookForPeers();
    void syncBlockchain();
    void getBlocks(uint32_t from, uint16_t count, bool &synced);
    void getBlock(std::vector<unsigned char> blockHeaderHash, uint64_t height);
    void broadCastNewBlockHeight(uint64_t height, std::vector<unsigned char> bestHeaderHash);
    void broadCastTransaction(Transaction tx);

    static bool isSynced();

};


#endif //TX_NETWORK_H
