#include <cstdlib>
#include "Peers.h"
#include "NetworkMessageHandler.h"
#include "../Tools/Log.h"
#include "../Chain.h"
#include "BanList.h"

void Peers::disconnect(ip_t ip) {
    Log(LOG_LEVEL_INFO) << "Peers::disconnect(" << ip << ")";
    auto found = this->peers.find(ip);

    if(found != this->peers.end()) {
        found->second->close();
        this->peers.erase(found);
        Log(LOG_LEVEL_INFO) << "disconnected:" << ip;
    }
}

PeerInterfacePtr Peers::getPeer(ip_t ip) {
    auto found = this->peers.find(ip);
    if(found != this->peers.end()) {
        return found->second;
    }

    return nullptr;
}

std::map<ip_t, PeerInterfacePtr> Peers::getPeers() {
    return this->peers;
}

bool Peers::isPeerAlreadyInList(ip_t ip) {
    auto found = this->peers.find(ip);

    // Peer is already in peer list
    return found != this->peers.end();
}

bool Peers::appendPeer(PeerInterfacePtr peer) {
    //@TODO: return false for IPs 127.xx.xx.xx
    BanList& banList = BanList::Instance();

    Log(LOG_LEVEL_INFO) << "Trying to append peer:" << peer->getIp();

    if(banList.isBanned(peer->getIp())) {
        Log(LOG_LEVEL_ERROR) << "Cannot appendPeer peer:" << peer->getIp() << " peer was banned";
        return false;
    }

    // Peer is already in peer list
    if(isPeerAlreadyInList(peer->getIp())) {
        Log(LOG_LEVEL_ERROR) << "Cannot appendPeer peer:" << peer->getIp() << " peer is already in peerlist";
        peer = nullptr;
        return false;
    }

    Chain &chain = Chain::Instance();

    this->peers.insert(std::make_pair(peer->getIp(), peer));
    Log(LOG_LEVEL_INFO) << "appended Peer, new peers list size : " << (uint64_t)this->peers.size();

    return true;
}

std::vector<PeerInterfacePtr> Peers::getRandomPeers(uint16_t count) {
    std::vector<PeerInterfacePtr> peerList;

    if(peers.size() <= count) {
        for(auto peer: peers) {
            peerList.emplace_back(peer.second);
        }
    } else {
        std::random_shuffle(peerList.begin(), peerList.end());

        uint16_t i = 0;
        for(auto peer: peers) {
            peerList.emplace_back(peer.second);
            if(i >= count) {
                return peerList;
            }
        }
    }

    return peerList;
}


void PeerServer::do_read_header()
{
    std::cout << "PeerServer::do_read_header" << std::endl;
    try {
        boost::asio::async_read(socket_,
                                boost::asio::buffer(read_msg_.data(), NetworkMessage::header_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    Log(LOG_LEVEL_INFO) << "do_read_header() ec message: " << ec.message();
                                    Log(LOG_LEVEL_INFO) << "do_read_header() ec value: " << ec.value();

                                    if (!ec) {
                                        if(read_msg_.decode_header()) {
                                            do_read_body();
                                        }
                                    } else {
                                        if(ec == boost::asio::error::eof) {
                                            do_connect();
                                        } else {
                                            Log(LOG_LEVEL_ERROR) << "PeerServer::do_read_header() " << ip
                                                                 << " terminated with error: " << ec.message();
                                            Peers &peers = Peers::Instance();
                                            peers.disconnect(ip);
                                        }
                                    }
                                });
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Peer: " << ip << " terminated with exception: " << e.what();
        Peers &peers = Peers::Instance();
        peers.disconnect(ip);
    }
}


void PeerServer::do_read_body()
{
    try {
        boost::asio::async_read(socket_,
                                boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
                                [this](boost::system::error_code ec, std::size_t /*length*/)
                                {

                                    Log(LOG_LEVEL_INFO) << "do_read_body() ec message: " << ec.message();
                                    Log(LOG_LEVEL_INFO) << "do_read_body() ec value: " << ec.value();

                                    if (!ec)
                                    {
                                        ip_t ip = socket_.remote_endpoint().address().to_string();
                                        Peers &peers = Peers::Instance();
                                        PeerInterfacePtr peer = peers.getPeer(ip);

                                        if(peer != nullptr) {

                                            NetworkMessage* msg2 = new NetworkMessage();
                                            std::memcpy(msg2->data(), read_msg_.data(), read_msg_.length());
                                            msg2->decode_header();

                                            Log(LOG_LEVEL_INFO) << "read_msg_: size:" << (uint64_t)msg2->length();
                                            std::thread t(&NetworkMessageHandler::handleNetworkMessage, msg2, peer);
                                            t.detach();

                                            do_read_header();
                                        } else {
                                            Log(LOG_LEVEL_ERROR) << "Peer with IP: " << ip  << " not found";
                                        }
                                    }
                                    else
                                    {
                                        if(ec == boost::asio::error::eof) {
                                            do_connect();
                                        } else {
                                            Log(LOG_LEVEL_ERROR) << "PeerServer::do_read_body() " << ip
                                                                 << " terminated with error: " << ec.message();
                                            Peers &peers = Peers::Instance();
                                            peers.disconnect(ip);
                                        }
                                    }
                                });
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Peer: " << ip << " terminated with exception: " << e.what();
        Peers &peers = Peers::Instance();
        peers.disconnect(ip);
    }
}

void PeerServer::do_write()
{
    if(write_msgs_.empty()) {
        Log(LOG_LEVEL_INFO) << "write_msgs_.empty()";
        deliverMutex.unlock();
        return;
    }

    if((uint32_t)write_msgs_.front().length() == 0) {
        Log(LOG_LEVEL_ERROR) << "PeerClient::do_write(): message length is 0";
        deliverMutex.unlock();
        return;
    }

    if(disconnected) {
        return;
    }

    Log(LOG_LEVEL_INFO) << "PeerClient::do_write(): length:" << (uint32_t)write_msgs_.front().length();

    try {
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(write_msgs_.front().data(),
                                                     write_msgs_.front().length()),
                                 [this](boost::system::error_code ec, std::size_t /*length*/)
                                 {
                                     std::cout << "ec message: " << ec.message() << std::endl;
                                     std::cout << "ec value: " << ec.value() << std::endl;
                                     if (!ec)
                                     {
                                         write_msgs_.pop_front();
                                         if (!write_msgs_.empty())
                                         {
                                             std::cout << "Server write: " << std::endl;
                                             do_write();
                                         } else {
                                             deliverMutex.unlock();
                                         }
                                     }
                                     else
                                     {
                                         Log(LOG_LEVEL_ERROR) << "PeerServer::do_write() " << ip << " terminated with error: " << ec.message();
                                         Peers &peers = Peers::Instance();
                                         peers.disconnect(ip);
                                     }
                                 });
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Peer: " << ip << " terminated with exception: " << e.what();
        Peers &peers = Peers::Instance();
        peers.disconnect(ip);
    }
}

void PeerServer::start()
{
    do_read_header();
}

void PeerServer::close()
{
    disconnected = true;
    try {
        socket_.close();
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "socket_.close() failed with exception: " << e.what();
    }
}

void PeerServer::deliver(NetworkMessage msg)
{
    Log(LOG_LEVEL_INFO) << "PeerServer::deliver()";
    deliverMutex.lock();
    bool write_in_progress = !write_msgs_.empty();
    write_msgs_.emplace_back(msg);
    Log(LOG_LEVEL_INFO) << "write_in_progress:" << write_in_progress;

    if(!write_in_progress) {
        do_write();
        return;
    }
    deliverMutex.unlock();
    Log(LOG_LEVEL_INFO) << "PeerServer::deliver() -> delivered";
}


ip_t PeerServer::getIp() {
    return ip;
}

void PeerServer::setIp(ip_t &ip) {
    this->ip = ip;
}

uint16_t PeerServer::getPort() const {
    return port;
}

void PeerServer::setPort(uint16_t port) {
    this->port = port;
}

std::vector<unsigned char> PeerServer::getName() {
    return name;
}

void PeerServer::setName(const std::vector<unsigned char> &name) {
    this->name = name;
}

uint8_t PeerServer::getStatus() {
    return status;
}

void PeerServer::setStatus(uint8_t status) {
    this->status = status;
}

uint16_t PeerServer::getVersion() {
    return version;
}

void PeerServer::setVersion(uint16_t version) {
    this->version = version;
}

uint32_t PeerServer::getBlockHeight() {
    return blockHeight;
}

void PeerServer::setBlockHeight(uint32_t blockHeight) {
    this->blockHeight = blockHeight;
}

uint64_t PeerServer::getClock() {
    return clock;
}

void PeerServer::setClock(uint64_t clock) {
    this->clock = clock;
}

std::string PeerServer::getDonationAddress() {
    return this->donationAddress;
}

void PeerServer::setDonationAddress(std::string donationAddress) {
    this->donationAddress = donationAddress;
}

void PeerClient::do_connect()
{
    if(connectionRetries > 10) {
        return;
    }
    connectionRetries++;
    Log(LOG_LEVEL_INFO) << "PeerClient::do_connect()";
    boost::asio::async_connect(socket_, endpoint_iterator_,
                               [this](boost::system::error_code ec, tcp::resolver::iterator)
                               {
                                   if (!ec)
                                   {
                                       do_read_header();
                                   } else {
                                       Log(LOG_LEVEL_INFO) << "PeerClient::do_connect() ec value:" << ec.value();
                                       Log(LOG_LEVEL_INFO) << "PeerClient::do_connect() ec message:" << ec.message();
                                       disconnected = true;
                                       this->disconnect();
                                   }
                               });
}

void PeerClient::do_read_header()
{
    Log(LOG_LEVEL_INFO) << "PeerClient::do_read_header()";
    boost::asio::async_read(socket_,
                            boost::asio::buffer(read_msg_.data(), NetworkMessage::header_length),
                            [this](boost::system::error_code ec, std::size_t /*length*/)
                            {
                                if (!ec && read_msg_.decode_header())
                                {
                                    do_read_body();
                                }
                                else
                                {
                                    Log(LOG_LEVEL_ERROR) << "PeerClient::do_read_header() " << ip
                                                         << " terminated with error: " << ec.message();
                                    if(ec == boost::asio::error::eof) {
                                        do_connect();
                                    } else {
                                        this->disconnect();
                                    }
                                }
                            });
}

void PeerClient::do_read_body()
{
    Log(LOG_LEVEL_INFO) << "PeerClient::do_read_body()";

    boost::asio::async_read(socket_,
                            boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
                            [this](boost::system::error_code ec, std::size_t /*length*/)
                            {
                                if (!ec)
                                {

                                    std::string ip = socket_.remote_endpoint().address().to_string();
                                    Peers &peers = Peers::Instance();
                                    PeerInterfacePtr peer = peers.getPeer(ip);

                                    if(peer != nullptr) {
                                        NetworkMessage* msg2 = new NetworkMessage(read_msg_.length());
                                        std::memcpy(msg2->data(), read_msg_.data(), read_msg_.length());
                                        msg2->decode_header();

                                        Log(LOG_LEVEL_INFO) << "read_msg_: size:" << (uint64_t)msg2->length();
                                        std::thread t(&NetworkMessageHandler::handleNetworkMessage, msg2, peer);
                                        t.detach();
                                        do_read_header();
                                    } else {
                                        Log(LOG_LEVEL_ERROR) << "Peer with IP: " << ip  << " not found";
                                    }
                                }
                                else
                                {
                                    Log(LOG_LEVEL_INFO) << "PeerClient::do_read_body() ec value:" << ec.value();
                                    Log(LOG_LEVEL_INFO) << "PeerClient::do_read_body() ec message:" << ec.message();
                                    if(ec == boost::asio::error::eof) {
                                        do_connect();
                                    } else {
                                        this->disconnect();
                                    }
                                }
                            });
}


void PeerClient::do_write()
{
    if(PeerClient::write_msgs_.empty()) {
        Log(LOG_LEVEL_INFO) << "write_msgs_.empty()";
        deliverMutex.unlock();
        return;
    }

    if((uint32_t)write_msgs_.front().length() == 0) {
        Log(LOG_LEVEL_ERROR) << "PeerClient::do_write(): message length is 0";
        deliverMutex.unlock();
        return;
    }

    if(disconnected) {
        return;
    }

    Log(LOG_LEVEL_INFO) << "PeerClient::do_write(): " <<
                        Hexdump::ucharToHexString((unsigned char*)write_msgs_.front().data(), (uint32_t)write_msgs_.front().length());

    try {
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(write_msgs_.front().data(),
                                                     write_msgs_.front().length()),
                                 [this](boost::system::error_code ec, std::size_t /*length*/)
                                 {
                                     if (!ec)
                                     {
                                         write_msgs_.pop_front();
                                         if (!write_msgs_.empty())
                                         {
                                             std::cout << "Server write: " << std::endl;
                                             do_write();
                                         } else {
                                             deliverMutex.unlock();
                                         }
                                     }
                                     else
                                     {
                                         if(ec == boost::asio::error::eof) {
                                             do_connect();
                                             deliverMutex.unlock();
                                         } else {
                                             this->disconnect();
                                         }
                                         //deliverMutex.unlock();
                                     }
                                 });
    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Peer: " << ip << " terminated with exception: " << e.what();
        disconnect();
        deliverMutex.unlock();
    }
}

void PeerClient::deliver(NetworkMessage msg)
{
    deliverMutex.lock();
    Log(LOG_LEVEL_INFO) << "PeerClient::deliver(): " <<
                        Hexdump::ucharToHexString((unsigned char*)msg.data(), (uint32_t)msg.length());
    bool write_in_progress = !write_msgs_.empty();
    write_msgs_.emplace_back(msg);
    Log(LOG_LEVEL_INFO) << "write_in_progress: " << write_in_progress;

    if(!write_in_progress) {
        Log(LOG_LEVEL_INFO) << "PeerClient::do_write0(): " <<
                            Hexdump::ucharToHexString((unsigned char*)write_msgs_.front().data(), (uint32_t)write_msgs_.front().length());
        do_write();
        return;
    }
    deliverMutex.unlock();
    Log(LOG_LEVEL_INFO) << "PeerClient::deliver() -> delivered";
}

void PeerClient::close()
{
    disconnected = true;
    work_.reset();
    //io_service_.stop();
    socket_.close();
    //io_service_.stop();
    //io_service_.post([this]() { socket_.close(); });
}


std::string PeerClient::getIp() {
    return ip;
}

void PeerClient::setIp(std::string &ip) {
    this->ip = ip;
}

uint16_t PeerClient::getPort() const {
    return port;
}

void PeerClient::setPort(uint16_t port) {
    this->port = port;
}

std::vector<unsigned char> PeerClient::getName() {
    return name;
}

void PeerClient::setName(const std::vector<unsigned char> &name) {
    this->name = name;
}

uint8_t PeerClient::getStatus() {
    return status;
}

void PeerClient::setStatus(uint8_t status) {
    this->status = status;
}

uint16_t PeerClient::getVersion() {
    return version;
}

void PeerClient::setVersion(uint16_t version) {
    this->version = version;
}

uint32_t PeerClient::getBlockHeight() {
    return blockHeight;
}

void PeerClient::setBlockHeight(uint32_t blockHeight) {
    this->blockHeight = blockHeight;
}

uint64_t PeerClient::getClock() {
    return clock;
}

void PeerClient::setClock(uint64_t clock) {
    this->clock = clock;
}

void PeerClient::disconnect() {
    disconnected = true;
    Log(LOG_LEVEL_INFO) << "Disconnect: " << ip;
    Peers &peers = Peers::Instance();
    peers.disconnect(ip);
}

std::string PeerClient::getDonationAddress() {
    return this->donationAddress;
}

void PeerClient::setDonationAddress(std::string donationAddress) {
    this->donationAddress = donationAddress;
}
