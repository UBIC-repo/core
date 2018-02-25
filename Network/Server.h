

#ifndef TX_SERVER_H
#define TX_SERVER_H

#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <boost/asio.hpp>
#include <unordered_map>
#include "NetworkMessage.h"
#include "Peers.h"
#include "../Tools/Log.h"
#include "BanList.h"

class Server {
private:
    void do_accept()
    {
        acceptor_.async_accept(socket_,
                               [this](boost::system::error_code ec)
                               {
                                   if (!ec)
                                   {
                                       std::string ip = socket_.remote_endpoint().address().to_string();
                                       Log(LOG_LEVEL_INFO) << "Incoming connection from: " << ip;

                                       BanList& banList = BanList::Instance();
                                       if(!banList.isBanned(ip)) {
                                           shared_ptr<PeerServer> peer(new PeerServer(std::move(socket_)));
                                           peer->start();
                                           peer->setIp(ip);

                                           Peers &peers = Peers::Instance();
                                           if (!peers.appendPeer(peer->get())) {
                                               peer->close();
                                           }
                                       } else {
                                           Log(LOG_LEVEL_INFO) << "cannot accept incoming connection from: "
                                                               << ip
                                                               << " because this ip is banned";
                                           socket_.close();
                                       }
                                   }

                                   do_accept();
                               });
    }

    Server(boost::asio::io_service& io_service,
            const tcp::endpoint& endpoint)
            : acceptor_(io_service, endpoint),
              socket_(io_service)
    {
        do_accept();
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
public:

    static Server& Instance(boost::asio::io_service& io_service,
                             const tcp::endpoint& endpoint) {
        static Server instance(io_service, endpoint);
        return instance;
    }
};


#endif //TX_SERVER_H
