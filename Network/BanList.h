
#ifndef TX_BANLIST_H
#define TX_BANLIST_H

#include <vector>
#include <map>
#include <cstdint>
#include <string>
#include "Peers.h"
#include "../Tools/Log.h"

#define BAN_INC_FOR_INVALID_MESSAGE 34
#define BAN_INC_FOR_INVALID_BLOCK 34
#define BAN_INC_FOR_UNWANTED_BLOCK 5
#define BAN_INC_INSTA_BAN 101
#define BAN_TRESHOLD 100

typedef std::string ip_t;

class BanList {
private:
    std::map<ip_t, uint16_t> banList;
public:

    static BanList& Instance(){
        static BanList instance;
        return instance;
    }

    bool isBanned(ip_t ip) {
        auto found = this->banList.find(ip);
        if(found != this->banList.end()) {
            return found->second > BAN_TRESHOLD;
        }

        return false;
    }

    std::map<ip_t, uint16_t> getBanList() {
            return this->banList;
    }

    bool removeFromBanList(ip_t ip) {
        auto found = this->banList.find(ip);

        if(found == this->banList.end()) {
            this->banList.erase(found);
            return true;
        }

        return false;
    }

    void appendBan(ip_t ip, uint16_t banInc) {
        if(ip.empty()) {
            return;
        }

        auto toBan = this->banList.find(ip);
        if(toBan != this->banList.end()) {
            if(toBan->second < BAN_TRESHOLD) {
                toBan->second += banInc;
                Log(LOG_LEVEL_INFO) << "node with IP:"
                                    << ip
                                    << " has new ban score:"
                                    << toBan->second;
            }
        } else {
            this->banList.insert(std::make_pair(ip, banInc));
        }

        if(this->isBanned(ip)) {
            Peers &peers = Peers::Instance();
            peers.disconnect(ip);
        }
    }
};


#endif //TX_BANLIST_H
