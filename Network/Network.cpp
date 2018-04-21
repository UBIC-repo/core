
#include <cstdint>
#include "Network.h"
#include "../TxPool.h"
#include "../Chain.h"
#include "Peers.h"
#include "BlockCache.h"
#include "NetworkCommands.h"
#include "../Time.h"
#include <boost/asio/ssl.hpp>
#include <regex>

bool Network::synced = false;
bool Network::isSyncing = false;
ip_t Network::myIP = "";
uint64_t Network::lastPeerLookup = 0;

using namespace boost::asio;

//@TODO add timeout after which the connection to Github is closed
/**
 * Will return 10 random node ips collected from Github
 */
std::vector<std::string> Network::getIpsFromGithub() {
    Log(LOG_LEVEL_INFO) <<  "Network::getIpsFromGithub()";
    //return std::vector<std::string>();
    std::vector<std::string> ipList;
    std::vector<std::string> ipList2;
    try {
        boost::system::error_code ec;
        io_service svc;
        ssl::context ctx(ssl::context::method::sslv23_client);
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

            Log(LOG_LEVEL_INFO) <<  "bytes_transferred rom Github: '" << (uint64_t)bytes_transferred;
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
    auto ipList = Network::getIpsFromGithub();

    for(auto ip : ipList) {

        if(ip == Network::myIP) {
            Log(LOG_LEVEL_INFO) << "Cannot add ip: " << ip << " because it is your own IP";
            continue;
        }

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

void Network::getMyIP() {
    try {
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("api.ipify.org", "80");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "GET / HTTP/1.0\r\n";
        request_stream << "Host: api.ipify.org\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        boost::asio::write(socket, request);
        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        // Check that response is OK.
        std::istream response_stream(&response);
        std::string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        std::string status_message;
        std::getline(response_stream, status_message);
        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            std::cout << "get my ip: Invalid response\n";
        }
        if (status_code != 200)
        {
            std::cout << "get my ip: Response returned with error code " << status_code << "\n";
        }

        // Read the response headers, which are terminated by a blank line.
        boost::asio::read_until(socket, response, "\r\n\r\n");

        // Process the response headers.
        std::string header;
        while (std::getline(response_stream, header) && header != "\r") {
            //std::cout << header << "\n";
        }

        std::ostringstream ss;
        ss << &response;


        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        while (boost::asio::read(socket, response,
                                 boost::asio::transfer_at_least(1), error))
            ss << &response;

        if (error != boost::asio::error::eof)
            throw boost::system::system_error(error);

        Network::myIP = ss.str();
        Log(LOG_LEVEL_INFO) << "My IP is: " << Network::myIP;
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << ", verify that ubicd is running or try /etc/init.d/ubic restart\n";
    }
}

void Network::syncBlockchain() {
    Peers &peers = Peers::Instance();
    Log(LOG_LEVEL_INFO) << "Network::syncBlockchain()";
    if (isSyncing) {
        Log(LOG_LEVEL_INFO) << "Network::syncBlockchain(), already syncing";
        //already syncing
        return;
    }

    isSyncing = true;

    if(peers.getPeers().size() < 10 && Time::getCurrentTimestamp() - lastPeerLookup > (3600*24) ) {
        Log(LOG_LEVEL_INFO) << "Going to look for peers";
        lastPeerLookup = Time::getCurrentTimestamp();
        std::thread t(&lookForPeers);
        t.detach();
    }

    Log(LOG_LEVEL_INFO) << "Network start syncing";
    Chain &chain = Chain::Instance();

    uint32_t currentBlockHeight;
    uint16_t batchSize = 100;

    while(!synced) {
        currentBlockHeight = chain.getCurrentBlockchainHeight() + 1;
        Network::getBlocks(currentBlockHeight, batchSize, synced);
    }
    Log(LOG_LEVEL_INFO) << "Node is synced";

    isSyncing = false;
}

void Network::askForBlocks(PeerInterfacePtr peer, AskForBlocks askForBlocks) {
    peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForBlocks));
}

void Network::askForBlock(PeerInterfacePtr peer, AskForBlock askForBlock) {
    peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForBlock));
}

void Network::askForBlockchainHeight(PeerInterfacePtr peer) {
    AskForBlockchainHeight askForBlockchainHeight;
    peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForBlockchainHeight));
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

        if(peers.getPeers().size() == 0 && Time::getCurrentTimestamp() - lastPeerLookup > 5 ) {
            Log(LOG_LEVEL_INFO) << "Second look for peers";
            lastPeerLookup = Time::getCurrentTimestamp();
            std::thread t(&lookForPeers);
            t.detach();
        }

        for(PeerInterfacePtr peer : peerList) {
            bool skip = false;
            Log(LOG_LEVEL_INFO) << "P1 :" << peer->getIp();

            // get a peer that isn't busy
            if(peer->getLastAsked() + 30 < Time::getCurrentTimestamp() || !blockCache.hasWork(peer->getIp())) {
                peer->setLastAsked(Time::getCurrentTimestamp());
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
                                std::thread t0(&Network::askForBlocks, peer, askForBlocks);
                                t0.detach();
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
                        batchNbr++;
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
                            std::thread t1(&Network::askForBlocks, peer, askForBlocks);
                            t1.detach();
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
                std::thread t2(&Network::askForBlockchainHeight, peer);
                t2.detach();

                if(!skip) {
                    // check for missing blocks by hash
                    uint32_t blockNbr = 0;
                    for (std::vector<unsigned char>& blockHeaderHash : blockCache.missingBlockHashList()) {
                        if (unbusyPeerNbr == blockNbr) {
                            AskForBlock askForBlock;
                            askForBlock.blockHeaderHash = blockHeaderHash;
                            std::thread t3(&Network::askForBlock, peer, askForBlock);
                            t3.detach();
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
        if(i % 120 == 0) {
            Log(LOG_LEVEL_INFO) << " i:" << i << " blocksReceived:" << blocksReceived;
            // if less than 5 blocks received within the last two minute we are probably synced
            if(blocksReceived < 5) {
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
    std::vector<PeerInterfacePtr> peerList = peers.getRandomPeers(12);
    Log(LOG_LEVEL_INFO) << "peerList.size(): " << (uint64_t)peerList.size();

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
