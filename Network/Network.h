
#ifndef TX_NETWORK_H
#define TX_NETWORK_H

#include <vector>
#include "../Transaction/Transaction.h"
#include "../Block/Block.h"
#include "Peers.h"
#include "NetworkCommands.h"

typedef std::string ip_t;

class Network {
private:
public:
    static bool synced;
    static uint64_t lastPeerLookup;
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
    static void askForBlocks(PeerInterfacePtr peer, AskForBlocks askForBlocks);
    static void askForBlock(PeerInterfacePtr peer, AskForBlock askForBlock);
    static void askForBlockchainHeight(PeerInterfacePtr peer);
    void getBlocks(uint32_t from, uint16_t count, bool &synced);
    void getBlock(std::vector<unsigned char> blockHeaderHash, uint64_t height);
    static void broadCastNewBlockHeight(uint64_t height, std::vector<unsigned char> bestHeaderHash);
    static void broadCastTransaction(TransactionForNetwork tx);

    static bool isSynced();

};


#endif //TX_NETWORK_H
