
#include <cstdint>
#include "Network.h"
#include "../TxPool.h"
#include "../Chain.h"
#include "Peers.h"
#include "BlockCache.h"
#include "NetworkCommands.h"
#include <boost/asio/ssl.hpp>
#include <regex>

bool Network::synced = false;
bool Network::isSyncing = false;

using namespace boost::asio;

//@TODO add timeout after which the connection to Github is closed
/**
 * Will return 10 random node ips collected from Github
 */
std::vector<std::string> Network::getIpsFromGithub() {
    //return std::vector<std::string>();
    std::vector<std::string> ipList;
    std::vector<std::string> ipList2;
    try {
        boost::system::error_code ec;
        io_service svc;
        ssl::context ctx(svc, ssl::context::method::sslv23_client);
        ssl::stream<ip::tcp::socket> ssock(svc, ctx);

        ip::tcp::resolver resolver(svc);
        auto it = resolver.resolve({"raw.githubusercontent.com", "443"});
        boost::asio::connect(ssock.lowest_layer(), it);

        ssock.handshake(ssl::stream_base::handshake_type::client);
        std::string request("GET /UBIC-repo/node-list/master/nodes HTTP/1.0\r\nHost: raw.githubusercontent.com\r\n\r\n");
        boost::asio::write(ssock, buffer(request));

        std::string response;

        size_t bytes_transferred = 0;
        size_t totalBytesTransfered = 0;
        do {
            char *buffer = (char *) malloc(256000 * sizeof(char));

            bytes_transferred = ssock.read_some(boost::asio::buffer(buffer, 256000), ec);
            totalBytesTransfered += bytes_transferred;
            response.append(buffer);

            Log(LOG_LEVEL_INFO) <<  "bytes_transferred rom Github: '" << bytes_transferred;
        } while(!ec);

        Log(LOG_LEVEL_INFO) <<  "Response received from Github: '" << response;

        std::regex rgx("(\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)");

        std::sregex_iterator next(response.begin(), response.end(), rgx);
        std::sregex_iterator end;
        while (next != end) {
            std::smatch match = *next;
            Log(LOG_LEVEL_INFO) << "found ip:" << match.str();
            ipList.emplace_back(match.str());
            next++;
        }
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Get ips from Github failed with exception : " << e.what();
    }

    std::random_shuffle(ipList.begin(), ipList.end());

    uint16_t i = 0;
    for(auto ip: ipList) {
        ipList2.emplace_back(ip);
        if(i >= 10) {
            return ipList2;
        }
        i++;
    }

    return ipList2;
}

void Network::lookForPeers() {
    Peers &peers = Peers::Instance();
    // Step 1 get some nodes from Github
    auto ipList = this->getIpsFromGithub();

    for(auto ip : ipList) {
        auto io_service = std::make_shared<boost::asio::io_service>();
        tcp::resolver resolver(*io_service);
        auto work = std::make_shared<boost::asio::io_service::work>(*io_service);
        auto endpoint_iterator = resolver.resolve({ip, NET_PORT});

        auto peer = std::make_shared<PeerClient>(io_service, endpoint_iterator, work);

        //std::shared_ptr<PeerClient> nPeer = peer->get();
        peer->setBlockHeight(0);
        peer->setIp(ip);
        if (peers.appendPeer(peer->get())) {
            peer->do_connect();

            auto io_service_run = [io_service]() {
                try {
                    io_service->run();
                    //io_service->stop();
                    Log(LOG_LEVEL_INFO) << "io_service terminated";
                }
                catch (const std::exception &e) {
                    Log(LOG_LEVEL_ERROR) << "io_service.run terminated with: " << e.what();
                }
            };
            std::thread t(io_service_run);
            t.detach();

            Chain &chain = Chain::Instance();

            // transmit our own block height
            CDataStream s(SER_DISK, 1);
            TransmitBlockchainHeight *transmitBlockchainHeight = new TransmitBlockchainHeight();
            transmitBlockchainHeight->height = chain.getCurrentBlockchainHeight();
            s << *transmitBlockchainHeight;

            NetworkMessage msg;
            msg.body_length(s.size());
            std::memcpy(msg.body(), s.data(), msg.body_length());
            msg.encode_header();

            peer->deliver(msg);

            //ask for blockheight
            CDataStream s2(SER_DISK, 1);
            AskForBlockchainHeight *askForBlockchainHeight = new AskForBlockchainHeight();
            s2 << *askForBlockchainHeight;

            NetworkMessage msg2;
            msg2.body_length(s2.size());
            std::memcpy(msg2.body(), s2.data(), msg2.body_length());
            msg2.encode_header();

            peer->deliver(msg2);
        } else {
            peer->close();
        }
    }

    // Step 2 ask for peers
    for(auto peer : peers.getPeers()) {
        AskForPeers askForPeers;
        peer.second->deliver(
                NetworkMessageHelper::serializeToNetworkMessage(askForPeers)
        );
    }

    // Wait 2 seconds

#if defined(_WIN32)
    Sleep(2000);
#else
    sleep(2);
#endif
}

void Network::syncBlockchain() {
    Peers &peers = Peers::Instance();
    Log(LOG_LEVEL_INFO) << "Network::syncBlockchain()";
    if (isSyncing) {
        Log(LOG_LEVEL_INFO) << "Network::syncBlockchain() is already syncing";
        //already syncing
        return;
    }

    if(peers.getPeers().size() < 10) {
        lookForPeers();
    }

    Log(LOG_LEVEL_INFO) << "Network start syncing";
    isSyncing = true;
    Chain &chain = Chain::Instance();

    uint32_t currentBlockHeight;
    uint16_t batchSize = 500;

    while(!synced) {
        currentBlockHeight = chain.getCurrentBlockchainHeight() + 1;
        Network::getBlocks(currentBlockHeight, batchSize, synced);
    }
    Log(LOG_LEVEL_INFO) << "Node is synced";

    isSyncing = false;
}

void Network::getBlocks(uint32_t from, uint16_t count, bool &synced) {
    synced = false;
    std::vector<uint32_t> neededBlockHeightList;
    std::vector< std::vector<unsigned char> > neededBlockHashList;

    // make needed block list
    for(uint32_t i = from; i < from + count; i++) {
        neededBlockHeightList.emplace_back(i);
    }

    Chain &chain = Chain::Instance();
    Peers &peers = Peers::Instance();
    BlockCache &blockCache = BlockCache::Instance();
    uint8_t peerBatch = 10;
    bool done = false;
    uint32_t i = 0;
    uint32_t blocksReceived = 0;

    while(!done) {

        uint32_t unbusyPeerNbr = 0;
        
        std::vector<PeerInterfacePtr> peerList = peers.getRandomPeers(6);

        for(PeerInterfacePtr peer : peerList) {
            bool skip = false;
            Log(LOG_LEVEL_INFO) << "P1 :" << peer->getIp();

            // get a peer that isn't busy
            if(!blockCache.hasWork(peer->getIp())) {

                Log(LOG_LEVEL_INFO) << "unbusy :" << peer->getIp() << " with blockHeight: " << peer->getBlockHeight();

                // if there is a missing batch, take it
                uint32_t batchNbr = 0;
                uint32_t batchCandidateSize = 0;
                uint64_t previousBlockHeight = 0;

                for(uint64_t blockHeight : neededBlockHeightList) {
                    if(blockHeight == previousBlockHeight + 1) {
                        batchCandidateSize++;
                    }
                    previousBlockHeight = blockHeight;

                    if(batchCandidateSize + 1 >= peerBatch) {
                        if(unbusyPeerNbr == batchNbr) {
                            AskForBlocks askForBlocks;
                            if(blockHeight < peerBatch) {
                                askForBlocks.startBlockHeight = 1;
                            } else {
                                askForBlocks.startBlockHeight = blockHeight - peerBatch;
                            }
                            askForBlocks.count = peerBatch;

                            if(peer->getBlockHeight() >= askForBlocks.startBlockHeight + askForBlocks.count) {
                                peer->deliver(
                                        NetworkMessageHelper::serializeToNetworkMessage(askForBlocks)
                                );
                                std::vector<uint32_t> blockHeightVector;
                                for (uint32_t z = 0; z < peerBatch; z++) {
                                    blockHeightVector.emplace_back((uint32_t) (askForBlocks.startBlockHeight + z));
                                }
                                blockCache.insertInBlockHeightAskedMap(peer.get()->getIp(), blockHeightVector);

                                Log(LOG_LEVEL_INFO) << "asked for batch, start:"
                                                    << askForBlocks.startBlockHeight
                                                    << " count:"
                                                    << askForBlocks.count;
                                unbusyPeerNbr++;
                                skip = true;
                            }
                        }
                        batchCandidateSize = 0;
                    }
                }

                if(!skip) {
                    // if there is no missing batch
                    uint32_t blockNbr = 0;
                    for (uint32_t blockHeight : neededBlockHeightList) {

                        if (unbusyPeerNbr == blockNbr && peer->getBlockHeight() >= blockHeight) {
                            AskForBlocks askForBlocks;
                            askForBlocks.startBlockHeight = blockHeight;
                            askForBlocks.count = 1;
                            NetworkMessage networkMessage = NetworkMessageHelper::serializeToNetworkMessage(
                                    askForBlocks
                            );
                            peer->deliver(
                                    networkMessage
                            );
                            std::vector<uint32_t> blockHeightVector;
                            blockHeightVector.emplace_back(blockHeight);
                            blockCache.insertInBlockHeightAskedMap(peer->getIp(), blockHeightVector);

                            Log(LOG_LEVEL_INFO) << "asked for block, height:"
                                                << askForBlocks.startBlockHeight;
                            skip = true;
                        }

                        blockNbr++;
                    }
                }

                // Ask peer for it's new block height
                AskForBlockchainHeight askForBlockchainHeight;
                peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForBlockchainHeight));

                if(!skip) {
                    // check for missing blocks by hash
                    uint32_t blockNbr = 0;
                    for (std::vector<unsigned char>& blockHeaderHash : blockCache.missingBlockHashList()) {
                        if (unbusyPeerNbr == blockNbr) {
                            AskForBlock askForBlock;
                            askForBlock.blockHeaderHash = blockHeaderHash;
                            peer->deliver(
                                    NetworkMessageHelper::serializeToNetworkMessage(askForBlock)
                            );
                            blockCache.insertInBlockHashAskedMap(peer->getIp(), blockHeaderHash);
                            neededBlockHashList.emplace_back(blockHeaderHash);

                            Log(LOG_LEVEL_INFO) << "asked for block, hash:"
                                                << askForBlock.blockHeaderHash;
                            unbusyPeerNbr++;
                        }
                    }
                }
                unbusyPeerNbr++;
            }
        }


#if defined(_WIN32)
        Sleep(1000);
#else
        sleep(1);
#endif
        //remove known blocks either in cache or in chain
        auto it = neededBlockHeightList.begin();
        while (it != neededBlockHeightList.end()) {
            if(chain.doesBlockExist(*it) || blockCache.isBlockInCache(*it)) {
                it = neededBlockHeightList.erase(it);
                blocksReceived++;
            } else {
                it++;
            }
        }

        auto it2 = neededBlockHashList.begin();
        while (it2 != neededBlockHashList.end()) {
            if(chain.doesBlockExist(*it2) || blockCache.isBlockInCache(*it2)) {
                it2 = neededBlockHashList.erase(it2);
                blocksReceived++;
            } else {
                it2++;
            }
        }

        if(neededBlockHeightList.empty()) {
            return;
        }

        i++;

        if(i % 20 == 0) {
            Log(LOG_LEVEL_INFO) << " i:" << i << " blocksReceived:" << blocksReceived;
            // if less than 4 blocks received within the last minute we are probably synced
            if(blocksReceived < 4) {
                synced = true;
                return;
            }
            blocksReceived = 0;
        }
    }
}

void Network::getBlock(std::vector<unsigned char> blockHeaderHash, uint64_t height) {

}

void Network::broadCastNewBlockHeight(uint64_t height, std::vector<unsigned char> bestHeaderHash) {

    TransmitBlockchainHeight transmitBlockchainHeight;

    transmitBlockchainHeight.height = height;
    transmitBlockchainHeight.bestHeaderHash = bestHeaderHash;

    Peers &peers = Peers::Instance();
    std::vector<PeerInterfacePtr> peerList = peers.getRandomPeers(50);
    Log(LOG_LEVEL_INFO) << "peerList.size(): " << peerList.size();

    for (auto &peer : peerList) {
        peer->deliver(
                NetworkMessageHelper::serializeToNetworkMessage(transmitBlockchainHeight)
        );
    }
}

void Network::broadCastTransaction(Transaction tx) {
    TransmitTransactions transmitTransaction;
    transmitTransaction.transactions.emplace_back(tx);

    Peers &peers = Peers::Instance();
    std::vector<PeerInterfacePtr> peerList = peers.getRandomPeers(10);
    for(auto &peer : peerList) {
        peer->deliver(
                NetworkMessageHelper::serializeToNetworkMessage(transmitTransaction)
        );
    }
}

bool Network::isSynced() {
    return synced;
}
