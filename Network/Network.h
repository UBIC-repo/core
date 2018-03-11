
#ifndef TX_NETWORK_H
#define TX_NETWORK_H

#include <vector>
#include "../Transaction/Transaction.h"
#include "../Block.h"

typedef std::string ip_t;

class Network {
private:
public:
    static bool synced;
    static bool isSyncing;
    static ip_t myIP;

    static Network& Instance(){
        static Network instance;
        return instance;
    }

    static std::vector<std::string> getIpsFromGithub();
    static void lookForPeers();
    static void getMyIP();
    void syncBlockchain();
    void getBlocks(uint32_t from, uint16_t count, bool &synced);
    void getBlock(std::vector<unsigned char> blockHeaderHash, uint64_t height);
    void broadCastNewBlockHeight(uint64_t height, std::vector<unsigned char> bestHeaderHash);
    void broadCastTransaction(Transaction tx);

    static bool isSynced();

};


#endif //TX_NETWORK_H
