
#ifndef TX_DB_H
#define TX_DB_H

#include <leveldb/db.h>
#include <vector>
#include <leveldb/status.h>
#include "../streams.h"
#include "../Tools/Hexdump.h"

class DB {
private:
    leveldb::DB* dbAddressStore = nullptr;
    leveldb::DB* dbBlockIndexStore = nullptr;
    leveldb::DB* dbNTPSKStore = nullptr;
    leveldb::DB* dbDSCCounterStore = nullptr;
    leveldb::DB* dbBlockHeadersStore = nullptr;
    leveldb::DB* dbMyTransactions = nullptr;
    leveldb::DB* dbVotes = nullptr;
public:
    DB();
    static DB& Instance(){
        static DB instance;
        return instance;
    }

    template < class Serializable >
    bool deserializeFromDb(uint8_t store, uint64_t key, Serializable& data) {
        std::vector<unsigned char> found = this->getFromDB(store, key);

        if(found.empty()) {
            return false;
        }

        CDataStream s(SER_DISK, 1);
        s.write((char*)found.data(), found.size());
        s >> data;

        return true;
    }


    template < class Serializable >
    bool deserializeFromDb(uint8_t store, std::vector<unsigned char> key, Serializable& data) {
        std::vector<unsigned char> found = this->getFromDB(store, key);

        if(found.empty()) {
            return false;
        }

        CDataStream s(SER_DISK, 1);
        s.write((char*)found.data(), found.size());
        s >> data;
        s.clear();

        return true;
    }

    template < class Serializable >
    bool serializeToDb(uint8_t store, std::vector<unsigned char> key, Serializable& data) {

        CDataStream s(SER_DISK, 1);
        s << data;

        std::vector<unsigned char> sVector(s.data(), s.data() + s.size());
        bool result = this->putInDB(store, key, sVector);
        s.clear();

        return result;
    }

    template < class Serializable >
    bool serializeToDb(uint8_t store, uint64_t key, Serializable& data) {
        std::string keyString = std::to_string(key);
        return serializeToDb(store, Hexdump::stringToCharVector(keyString), data);
    }

    leveldb::DB* getDbForStore(uint8_t store);
    std::vector< std::vector<unsigned char> > getAllKeys(uint8_t store);
    bool putInDB(uint8_t store, std::string key, std::vector<unsigned char> value);
    bool putInDB(uint8_t store, std::vector<unsigned char> key, std::vector<unsigned char> value);
    bool putInDB(uint8_t store, uint64_t key, std::vector<unsigned char> value);
    std::vector<unsigned char> getFromDB(uint8_t store, std::string keyString);
    std::vector<unsigned char> getFromDB(uint8_t store, std::vector<unsigned char> key);
    std::vector<unsigned char> getFromDB(uint8_t store, uint64_t key);
    bool isInDB(uint8_t store, std::vector<unsigned char> key);
    bool removeFromDB(uint8_t store, std::vector<unsigned char> key);
};


#endif //TX_DB_H
