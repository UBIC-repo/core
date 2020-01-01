
#include "TxPool.h"
#include "Tools/Log.h"
#include "Block.h"
#include "Transaction/TransactionHelper.h"
#include "Network/NetworkMessage.h"
#include "Chain.h"
#include "Network/Network.h"
#include "Time.h"

bool TxPool::isTxInputPresent(TxIn txIn) {
    if(txIn.getInAddress().empty()) {
        return false;
    }

    std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(txIn.getInAddress()));
    return txInIt != this->txInputs.end();
}

bool TxPool::isTxInputPresent(TransactionForNetwork* transactionForNetwork) {
    Transaction transaction = transactionForNetwork->getTransaction();

    if(TransactionHelper::isRegisterPassport(&transaction)) {
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction);

        std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
        return txInIt != this->txInputs.end();
    } else {
        for (TxIn txIn: transaction.getTxIns()) {
            if (this->isTxInputPresent(txIn)) {
                return true;
            }
        }
    }

    return false;
}

std::unordered_map<std::string, TransactionForNetwork> TxPool::getTransactionList() {
    return this->transactionList;
}

void TxPool::setTransactionList(std::unordered_map<std::string, TransactionForNetwork> transactionList) {
    this->transactionList = transactionList;
}

void TxPool::popTransaction(std::vector<unsigned char> txId) {
    std::unordered_map<std::string, TransactionForNetwork>::iterator txForNetworkIt = this->transactionList.find(Hexdump::vectorToHexString(txId));
    if(txForNetworkIt != this->transactionList.end()) {
        Transaction transaction = txForNetworkIt->second.getTransaction();
        if(TransactionHelper::isRegisterPassport(&transaction)) {
            std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction);

            auto found = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
            if (found != this->txInputs.end()) {
                this->txInputs.erase(found);
            }
        } else {
            for (TxIn txIn: transaction.getTxIns()) {
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

bool TxPool::appendTransaction(TransactionForNetwork transactionForNetwork) {
    Chain& chain = Chain::Instance();
    Transaction transaction = transactionForNetwork.getTransaction();
    if(!TransactionHelper::verifyNetworkTx(&transactionForNetwork)) {
        Log(LOG_LEVEL_ERROR) << "cannot append transaction to txpool because it isn't valid";
        return false;
    }

    if(this->isTxInputPresent(&transactionForNetwork)) {
        Log(LOG_LEVEL_WARNING) << "cannot append transaction to txpool because one of it's input has another transaction pending";
        return false;
    }

    transaction.setTimestamp(Time::getCurrentTimestamp());
    transactionForNetwork.setTransaction(transaction);

    this->transactionList.insert(
            std::pair<std::string, TransactionForNetwork>(
                    Hexdump::vectorToHexString(TransactionHelper::getTxId(&transaction)),
                    transactionForNetwork
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

    std::thread t1(&Network::broadCastTransaction, transactionForNetwork);
    t1.detach();

    return true;
}

void TxPool::appendTransactionsFromBlock(Block* block) {
    for(auto tx : block->getTransactions()) {
        TransactionForNetwork transactionForNetwork;
        transactionForNetwork.setTransaction(tx);
        this->appendTransaction(transactionForNetwork);
    }

    for(auto tx : block->getHeader()->getVotes()) {
        TransactionForNetwork transactionForNetwork;
        transactionForNetwork.setTransaction(tx);
        this->appendTransaction(transactionForNetwork);
    }
}

uint32_t TxPool::getTxCount() {
    return (uint32_t)this->transactionList.size();
}

TransactionForNetwork* TxPool::popTransaction() {
    if(getTxCount() == 0) {
        return nullptr;
    }
    auto tb = this->transactionList.begin();
    TransactionForNetwork* rval = new TransactionForNetwork();
    *rval = tb->second;
    this->transactionList.erase(tb->first);

    for(TxIn txIn: rval->getTransaction().getTxIns()) {
        this->txInputs.erase(Hexdump::vectorToHexString(txIn.getInAddress()));
    }

    return rval;
}
