
#ifndef TX_TXPOOL_H
#define TX_TXPOOL_H

#include <string>
#include <vector>
#include <unordered_map>
#include "Transaction/Transaction.h"
#include "Block.h"

class TxPool {
private:
    std::unordered_map<std::string, Transaction> transactionList;
    std::unordered_map<std::string, TxIn> txInputs;

    bool isTxInputPresent(TxIn txIn);
    bool isTxInputPresent(Transaction* transaction);
public:
    static TxPool& Instance(){
        static TxPool instance;
        return instance;
    }

    std::unordered_map<std::string, Transaction> getTransactionList();
    void setTransactionList(std::unordered_map<std::string, Transaction> transactionList);
    void popTransaction(std::vector<unsigned char> txId);
    bool appendTransaction(Transaction transaction);
    void appendTransactionsFromBlock(Block* block);
    uint32_t getTxCount();
    Transaction* popTransaction();
};


#endif //TX_TXPOOL_H
