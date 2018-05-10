
#include "TxPool.h"
#include "Tools/Log.h"
#include "Block.h"
#include "Transaction/TransactionHelper.h"
#include "Network/NetworkMessage.h"
#include "Chain.h"
#include "Network/Network.h"

bool TxPool::isTxInputPresent(TxIn txIn) {
    if(txIn.getInAddress().empty()) {
        return false;
    }

    std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(txIn.getInAddress()));
    return txInIt != this->txInputs.end();
}

bool TxPool::isTxInputPresent(Transaction* transaction) {
    if(TransactionHelper::isRegisterPassport(transaction)) {
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(transaction);

        std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
        return txInIt != this->txInputs.end();
    } else {
        for (TxIn txIn: transaction->getTxIns()) {
            if (this->isTxInputPresent(txIn)) {
                return true;
            }
        }
    }

    return false;
}

std::unordered_map<std::string, Transaction> TxPool::getTransactionList() {
    return this->transactionList;
}

void TxPool::setTransactionList(std::unordered_map<std::string, Transaction> transactionList) {
    this->transactionList = transactionList;
}

void TxPool::popTransaction(std::vector<unsigned char> txId) {
    std::unordered_map<std::string, Transaction>::iterator txIt = this->transactionList.find(Hexdump::vectorToHexString(txId));
    if(txIt != this->transactionList.end()) {
        if(TransactionHelper::isRegisterPassport(&txIt->second)) {
            std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&txIt->second);

            auto found = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
            if (found != this->txInputs.end()) {
                this->txInputs.erase(found);
            }
        } else {
            for (TxIn txIn: txIt->second.getTxIns()) {
                auto found = this->txInputs.find(Hexdump::vectorToHexString(txIn.getInAddress()));
                if (found != this->txInputs.end()) {
                    this->txInputs.erase(found);
                }
            }
        }

        this->transactionList.erase(Hexdump::vectorToHexString(txId));
    } else {
        Log(LOG_LEVEL_INFO) << "popTransaction txId:" << txId << " not found";
    }
}

bool TxPool::appendTransaction(Transaction transaction) {
    Chain& chain = Chain::Instance();
    if(!TransactionHelper::verifyTx(&transaction, IGNORE_IS_IN_HEADER, chain.getBestBlockHeader())) {
        Log(LOG_LEVEL_ERROR) << "cannot append transaction to txpool because it isn't valid";
        return false;
    }

    if(this->isTxInputPresent(&transaction)) {
        Log(LOG_LEVEL_ERROR) << "cannot append transaction to txpool because one of it's input has another transaction pending";
        return false;
    }

    this->transactionList.insert(
            std::pair<std::string, Transaction>(
                    Hexdump::vectorToHexString(TransactionHelper::getTxId(&transaction)),
                    transaction
            )
    );

    if(TransactionHelper::isRegisterPassport(&transaction)) {
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction);
        this->txInputs.insert(std::make_pair(Hexdump::vectorToHexString(passportHash), transaction.getTxIns().front()));
    } else {
        for (TxIn txIn: transaction.getTxIns()) {
            this->txInputs.insert(std::make_pair(Hexdump::vectorToHexString(txIn.getInAddress()), txIn));
        }
    }

    std::thread t1(&Network::broadCastTransaction, transaction);
    t1.detach();

    return true;
}

void TxPool::appendTransactionsFromBlock(Block* block) {
    for(auto tx : block->getTransactions()) {
        this->appendTransaction(tx);
    }

    for(auto tx : block->getHeader()->getVotes()) {
        this->appendTransaction(tx);
    }
}

uint32_t TxPool::getTxCount() {
    return (uint32_t)this->transactionList.size();
}

Transaction* TxPool::popTransaction() {
    if(getTxCount() == 0) {
        return nullptr;
    }
    auto tb = this->transactionList.begin();
    Transaction* rval = new Transaction();
    *rval = tb->second;
    this->transactionList.erase(tb->first);

    for(TxIn txIn: rval->getTxIns()) {
        this->txInputs.erase(Hexdump::vectorToHexString(txIn.getInAddress()));
    }

    return rval;
}
