
#ifndef TX_PEERS_H
#define TX_PEERS_H

#include <unordered_map>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <memory>
#include <thread>
#include <set>
#include <utility>
#include <boost/asio.hpp>
#include <unordered_map>
#include <mutex>
#include "NetworkMessage.h"

#define STATUS_UNSYNCED 0
#define STATUS_SYNCED 1

typedef std::shared_ptr<PeerInterface> PeerInterfacePtr;

class Peers {
private:
    std::map<ip_t, PeerInterfacePtr> peers;
public:
    static Peers& Instance(){
        static Peers instance;
        return instance;
    }

    void disconnect(ip_t ip);
    PeerInterfacePtr getPeer(ip_t ip);
    std::map<ip_t, PeerInterfacePtr> getPeers();
    bool appendPeer(PeerInterfacePtr peer);
    bool isPeerAlreadyInList(ip_t ip);
    std::vector<PeerInterfacePtr> getRandomPeers(uint16_t count);
};


class PeerServer: public PeerInterface,
                  public std::enable_shared_from_this<PeerServer> {
private:
    ip_t ip;
    uint16_t port;
    std::vector<unsigned char> name;
    uint8_t status;
    uint16_t version;
    uint32_t blockHeight;
    uint64_t clock;
    std::mutex deliverMutex;
    bool disconnected = false;
    std::string donationAddress;
    uint64_t lastAsked = 0;

    void do_read_header();
    void do_read_body();
    void do_write();

    tcp::socket socket_;
    NetworkMessage read_msg_;
    std::deque<NetworkMessage> write_msgs_;

public:

    PeerServer(tcp::socket socket)
            : socket_(std::move(socket))
    {
    }

    std::shared_ptr<PeerServer> get() {
        return shared_from_this();
    }

    void do_connect() {};
                      
    uint64_t getLastAsked() {
        return lastAsked;
    }

    void setLastAsked(uint64_t lastAsked) {
        this->lastAsked = lastAsked;
    }

    void start();
    void close();
    void deliver(NetworkMessage msg);
    ip_t getIp();
    void setIp(ip_t &ip);
    uint16_t getPort() const;
    void setPort(uint16_t port);
    std::vector<unsigned char> getName();
    void setName(const std::vector<unsigned char> &name);
    uint8_t getStatus();
    void setStatus(uint8_t status);
    uint16_t getVersion();
    void setVersion(uint16_t version);
    uint32_t getBlockHeight();
    void setBlockHeight(uint32_t blockHeight);
    uint64_t getClock();
    void setClock(uint64_t clock);
    std::string getDonationAddress();
    void setDonationAddress(std::string donationAddress);
};

class PeerClient: public PeerInterface,
                  public std::enable_shared_from_this<PeerClient> {
private:
    bool disconnected = false;
    uint8_t connectionRetries = 0;
    ip_t ip;
    uint16_t port;
    std::vector<unsigned char> name;
    uint8_t status;
    uint16_t version;
    uint32_t blockHeight;
    uint64_t clock;
    std::mutex deliverMutex;
    std::string donationAddress;
    uint64_t lastAsked = 0;

    void do_read_header();
    void do_read_body();
    void do_write();

    boost::asio::io_service& io_service_;
    tcp::socket socket_;
    NetworkMessage read_msg_;
    std::deque<NetworkMessage> write_msgs_;
    tcp::resolver::iterator endpoint_iterator_;
    std::shared_ptr<boost::asio::io_service::work> work_;

public:
    PeerClient(std::shared_ptr<boost::asio::io_service> io_service,
               tcp::resolver::iterator endpoint_iterator,
               std::shared_ptr<boost::asio::io_service::work> work
    )
            : io_service_(*io_service),
              socket_(*io_service)
    {
        endpoint_iterator_ = endpoint_iterator;
        work_ = work;
    }

    void do_connect();

    std::shared_ptr<PeerClient> get() {
        return shared_from_this();
    }
                      
    uint64_t getLastAsked() {
        return lastAsked;
    }

    void setLastAsked(uint64_t lastAsked) {
        this->lastAsked = lastAsked;
    }

    void deliver(NetworkMessage msg);
    void close();
    ip_t getIp();
    void setIp(ip_t &ip);
    uint16_t getPort() const;
    void setPort(uint16_t port);
    std::vector<unsigned char> getName();
    void setName(const std::vector<unsigned char> &name);
    uint8_t getStatus();
    void setStatus(uint8_t status);
    uint16_t getVersion();
    void setVersion(uint16_t version);
    uint32_t getBlockHeight();
    void setBlockHeight(uint32_t blockHeight);
    uint64_t getClock();
    void setClock(uint64_t clock);
    void disconnect();
    std::string getDonationAddress();
    void setDonationAddress(std::string donationAddress);
};

#endif //TX_PEERS_H
