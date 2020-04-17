
#ifndef TX_NETWORKMESSAGEHANDLER_H
#define TX_NETWORKMESSAGEHANDLER_H

#include <mutex>
#include "NetworkMessage.h"
#include "NetworkCommands.h"

typedef std::shared_ptr<PeerInterface> PeerInterfacePtr;

class NetworkMessageHandler {
private:

    static void handleAskForBlocks(AskForBlocks askForBlocks, PeerInterfacePtr recipient);
    static void handleAskForBlock(AskForBlock askForBlock, PeerInterfacePtr recipient);
    static void handleAskForPeers(PeerInterfacePtr recipient);
    static void handleAskForBlockchainHeight(PeerInterfacePtr recipient);
    static void handleAskForBestBlockHeader(PeerInterfacePtr recipient);
    static void handleAskForVersion(PeerInterfacePtr recipient);
    static void handleAskForStatus(PeerInterfacePtr recipient);
    static void handleAskForDonationAddress(PeerInterfacePtr recipient);
    static void handleTransmitBlock(std::vector<unsigned char> block, PeerInterfacePtr recipient);
    static void handleTransmitTransactions(TransmitTransactions *transmitBlocks, PeerInterfacePtr recipient);
    static void handleTransmitBlock(TransmitBlock *transmitBlock, PeerInterfacePtr recipient);
    static void handleTransmitBlocks(TransmitBlocks *transmitBlocks, PeerInterfacePtr recipient);
    static void handleTransmitPeers(TransmitPeers *transmitPeers, PeerInterfacePtr recipient);
    static void handleTransmitBlockchainHeight(TransmitBlockchainHeight *transmitBlockchainHeight, PeerInterfacePtr recipient);
    static void handleTransmitBestBlockHeader(TransmitBestBlockHeader *transmitBestBlockHeader, PeerInterfacePtr recipient);
    static void handleTransmitVersion(TransmitVersion *transmitVersion, PeerInterfacePtr recipient);
    static void handleTransmitStatus(TransmitStatus *transmitStatus, PeerInterfacePtr recipient);
    static void handleTransmitLeave(PeerInterfacePtr recipient);
    static void handleTransmitDonationAddress(TransmitDonationAddress* transmitDonationAddress, PeerInterfacePtr recipient);
public:
    static void handleNetworkMessage(NetworkMessage *networkMessage, PeerInterfacePtr recipient);
};


#endif //TX_NETWORKMESSAGEHANDLER_H
