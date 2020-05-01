
#ifndef TX_TX_H
#define TX_TX_H

#define IS_NOT_IN_HEADER 0
#define IS_IN_HEADER 1
#define IGNORE_IS_IN_HEADER 2

#include <vector>
#include <list>
#include "TxIn.h"
#include "TxOut.h"

class Transaction {
private:
    uint8_t network; // To avoid a transaction from the testnet being broadcasted on the main net
    std::vector<TxIn> txIns;
    std::vector<TxOut> txOuts;
    uint32_t timestamp = 0; // only used within the transaction pool
public:
    void addTxIn(TxIn txIn);
    void setTxIns(std::vector<TxIn> txIns);
    std::vector <TxIn> getTxIns();
    void addTxOut(TxOut txOut);
    void setTxOuts(std::vector<TxOut> txOuts);
    std::vector <TxOut> getTxOuts();
    uint8_t getNetwork() const;
    void setNetwork(uint8_t network);
    uint32_t getTimestamp();
    void setTimestamp(uint32_t timestamp);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(network);
        READWRITE(txIns);
        READWRITE(txOuts);
    }
};

class TransactionForNetwork {
private:
    Transaction transaction;
    uint8_t additionalPayloadType = 0;
    std::vector<unsigned char> additionalPayload = std::vector<unsigned char>(); // is intended to contain the DSC certificate for register passport transactions
public:
    void setTransaction(Transaction transaction) {
        this->transaction = transaction;
    }

    Transaction getTransaction() {
        return this->transaction;
    }

    void setAdditionalPayload(std::vector<unsigned char> additionalPayload) {
        this->additionalPayload = additionalPayload;
    }

    std::vector<unsigned char> getAdditionalPayload() {
        return this->additionalPayload;
    }

    void setAdditionalPayloadType(uint8_t additionalPayloadType) {
        this->additionalPayloadType = additionalPayloadType;
    }

    uint8_t getAdditionalPayloadType() {
        return this->additionalPayloadType;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(transaction);
        READWRITE(additionalPayloadType);
        READWRITE(additionalPayload);
    }
};

class TransactionForStore {
private:
    std::vector<unsigned char> blockHash;
    Transaction tx;
public:
    const std::vector<unsigned char> getBlockHash() {
        return blockHash;
    }

    void setBlockHash(std::vector<unsigned char> blockHash) {
        this->blockHash = blockHash;
    }

    Transaction getTx() {
        return tx;
    }

    void setTx(Transaction &tx) {
        this->tx = tx;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockHash);
        READWRITE(tx);
    }
};


#endif //TX_TX_H
