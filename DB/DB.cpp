
#include "DB.h"
#include "../ChainParams.h"
#include "../Tools/Log.h"
#include "../FS/FS.h"

DB::DB() {

    leveldb::Options options;
    options.create_if_missing = true;

    /*
     * AddressStore
     */
    char pAddressStore[512];
    FS::charPathFromVectorPath(pAddressStore, FS::getAddressStorePath());

    leveldb::Status statusAddressStore = leveldb::DB::Open(options, pAddressStore, &this->dbAddressStore);

    /*
     * BlockIndexStore
     */
    char pBlockIndexStore[512];
    FS::charPathFromVectorPath(pBlockIndexStore, FS::getBlockIndexStorePath());

    leveldb::Status statusBlockIndexStore = leveldb::DB::Open(options, pBlockIndexStore, &this->dbBlockIndexStore);

    /*
     * NTPSKStore
     */
    char pNTPSKStore[512];
    FS::charPathFromVectorPath(pNTPSKStore, FS::getNTPSKStorePath());

    leveldb::Status statusNTPSKStore = leveldb::DB::Open(options, pNTPSKStore, &this->dbNTPSKStore);

    /*
     * DSCCounterStore
     */
    char pDSCCounterStore[512];
    FS::charPathFromVectorPath(pDSCCounterStore, FS::getDSCCounterStorePath());

    leveldb::Status statusDSCCounterStore = leveldb::DB::Open(options, pDSCCounterStore, &this->dbDSCCounterStore);

    /*
     * BlockHeadersStore
     */
    char pBlockHeadersStore[512];
    FS::charPathFromVectorPath(pBlockHeadersStore, FS::getBlockHeadersPath());

    leveldb::Status statusBlockHeadersStore = leveldb::DB::Open(options, pBlockHeadersStore, &this->dbBlockHeadersStore);

    /*
     * MyTransactionsStore
     */
    char pMyTransactions[512];
    FS::charPathFromVectorPath(pMyTransactions, FS::getMyTransactionsPath());

    leveldb::Status statusMyTransactions = leveldb::DB::Open(options, pMyTransactions, &this->dbMyTransactions);

    /*
     * Votes
     */
    char pVotes[512];
    FS::charPathFromVectorPath(pVotes, FS::getVotesPath());

    leveldb::Status statusVotes = leveldb::DB::Open(options, pVotes, &this->dbVotes);
}

leveldb::DB* DB::getDbForStore(uint8_t store) {
    leveldb::DB* db;
    switch (store) {
        case DB_ADDRESS_STORE:
            db = this->dbAddressStore;
            break;
        case DB_BLOCK_INDEX:
            db = this->dbBlockIndexStore;
            break;
        case DB_NTPSK_ALREADY_USED:
            db = this->dbNTPSKStore;
            break;
        case DB_DSC_ATTACHED_PASSPORTS_COUNTER:
            db = this->dbDSCCounterStore;
            break;
        case DB_BLOCK_HEADERS:
            db = this->dbBlockHeadersStore;
            break;
        case DB_MY_TRANSACTIONS:
            db = this->dbMyTransactions;
            break;
        case DB_VOTES:
            db = this->dbVotes;
            break;
        default:
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Unknown db store " << store;
            return nullptr;
    }

    return db;
}

std::vector< std::vector<unsigned char> > DB::getAllKeys(uint8_t store) {

    leveldb::DB* db = this->getDbForStore(store);
    std::vector< std::vector<unsigned char> > response;

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        leveldb::Slice key = it->key();
        response.emplace_back(std::vector<unsigned char>(key.data(), key.data() + key.size()));
    }
    assert(it->status().ok());  // Check for any errors found during the scan
    delete it;

    return response;
}

bool DB::putInDB(uint8_t store, std::string key, std::vector<unsigned char> value) {

    std::string valueString((char*)value.data(), value.size());

    leveldb::WriteOptions writeOptions;

    leveldb::DB* db = this->getDbForStore(store);
    if(db == nullptr) {
        return false;
    }

    leveldb::Status status = db->Put(writeOptions, key, valueString);

    if(!status.ok()) {
        Log(LOG_LEVEL_ERROR) << "Failed to write to Store: " << store << " error: " << status.ToString();
        return false;
    }

    //Log(LOG_LEVEL_INFO) << "wrote key:" << key << " Store:" << store << " Value:" << value;

    return true;
}

bool DB::putInDB(uint8_t store, std::vector<unsigned char> key, std::vector<unsigned char> value) {
    std::string keyString((char*)key.data(), key.size());

    return this->putInDB(store, keyString, value);
}

bool DB::putInDB(uint8_t store, uint64_t key, std::vector<unsigned char> value) {
    std::string nKey = std::to_string(key);

    return this->putInDB(store, nKey, value);
}

std::vector<unsigned char> DB::getFromDB(uint8_t store, std::string keyString) {
    std::string valueString;

    leveldb::ReadOptions readOptions;

    leveldb::DB* db = this->getDbForStore(store);
    if(db == nullptr) {
        return std::vector<unsigned char>();
    }

    leveldb::Status status = db->Get(readOptions, keyString, &valueString);

    if(valueString.empty() || !status.ok()) {
        return std::vector<unsigned char>();
    }

    std::vector<unsigned char> rVector(valueString.c_str(), valueString.c_str() + valueString.length());

    //Log(LOG_LEVEL_DEBUG) << "Retrieved key:" << keyString << " Store:" << store << " Value:" << rVector;

    return rVector;
}


std::vector<unsigned char> DB::getFromDB(uint8_t store, std::vector<unsigned char> key) {
    std::string keyString((char*)key.data(), key.size());

    return this->getFromDB(store, keyString);
}

std::vector<unsigned char> DB::getFromDB(uint8_t store, uint64_t key) {
    std::string keyString = std::to_string(key);

    return this->getFromDB(store, keyString);
}

bool DB::isInDB(uint8_t store, std::vector<unsigned char> key) {

    std::string keyString((char*)key.data(), key.size());
    std::string valueString;

    leveldb::ReadOptions readOptions;

    leveldb::DB* db = this->getDbForStore(store);
    if(db == nullptr) {
        return false;
    }

    leveldb::Status status = db->Get(readOptions, keyString, &valueString);


    return status.ok();
}

bool DB::removeFromDB(uint8_t store, std::vector<unsigned char> key) {
    std::string keyString((char*)key.data(), key.size());
    std::string valueString;

    leveldb::WriteOptions writeOptions;

    leveldb::DB* db = this->getDbForStore(store);
    if(db == nullptr) {
        return false;
    }

    leveldb::Status status = db->Delete(writeOptions, keyString);

    return status.ok();
}
