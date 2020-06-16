
#include "TxPool.h"
#include "Tools/Log.h"
#include "Block/Block.h"
#include "Transaction/TransactionHelper.h"
#include "Chain.h"
#include "Network/Network.h"
#include "Tools/Time.h"
#include "Crypto/X509Helper.h"
#include "Transaction/TransactionVerify.h"

std::mutex TxPool::transactionListLock;
std::mutex TxPool::txInputsLock;

bool TxPool::isTxInputPresent(TxIn txIn) {
    if(txIn.getInAddress().empty()) {
        return false;
    }

    txInputsLock.lock();
    std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(txIn.getInAddress()));
    bool result = txInIt != this->txInputs.end();
    txInputsLock.unlock();
    return result;
}

bool TxPool::isTxInputPresent(TransactionForNetwork* transactionForNetwork) {
    Transaction transaction = transactionForNetwork->getTransaction();

    if(TransactionHelper::isRegisterPassport(&transaction)) {
        X509* x509 = X509Helper::vectorToCert(transactionForNetwork->getAdditionalPayload());
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction, x509);
        X509_free(x509);

        txInputsLock.lock();
        std::unordered_map<std::string, TxIn>::iterator txInIt = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
        bool result = txInIt != this->txInputs.end();
        txInputsLock.unlock();
        return result;
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
    transactionListLock.lock();
    std::unordered_map<std::string, TransactionForNetwork> transactionListCopy(this->transactionList);
    transactionListLock.unlock();
    return transactionListCopy;
}

void TxPool::setTransactionList(std::unordered_map<std::string, TransactionForNetwork> transactionList) {
    transactionListLock.lock();
    this->transactionList = transactionList;
    transactionListLock.unlock();
}

void TxPool::popTransaction(std::vector<unsigned char> txId) {
    transactionListLock.lock();
    std::unordered_map<std::string, TransactionForNetwork>::iterator txForNetworkIt = this->transactionList.find(Hexdump::vectorToHexString(txId));
    if(txForNetworkIt != this->transactionList.end()) {
        Transaction transaction = txForNetworkIt->second.getTransaction();
        if(TransactionHelper::isRegisterPassport(&transaction)) {
            std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction, X509Helper::vectorToCert(txForNetworkIt->second.getAdditionalPayload()));

            txInputsLock.lock();
            auto found = this->txInputs.find(Hexdump::vectorToHexString(passportHash));
            if (found != this->txInputs.end()) {
                this->txInputs.erase(found);
            }
            txInputsLock.unlock();
        } else {
            for (TxIn txIn: transaction.getTxIns()) {
                txInputsLock.lock();
                auto found = this->txInputs.find(Hexdump::vectorToHexString(txIn.getInAddress()));
                if (found != this->txInputs.end()) {
                    this->txInputs.erase(found);
                }
                txInputsLock.unlock();
            }
        }

        this->transactionList.erase(Hexdump::vectorToHexString(txId));
    } else {
        Log(LOG_LEVEL_INFO) << "popTransaction txId:" << txId << " not found";
    }
    transactionListLock.unlock();
}

bool TxPool::appendTransaction(TransactionForNetwork transactionForNetwork, bool broadcast, TransactionError *transactionError) {
    Chain &chain = Chain::Instance();

    transactionForNetwork.setTimestampReceived(Time::getCurrentTimestamp());
    transactionForNetwork.setTimestampLastBroadcasted(Time::getCurrentTimestamp());

    Transaction transaction = transactionForNetwork.getTransaction();
    if (!TransactionVerify::verifyNetworkTx(&transactionForNetwork, transactionError)) {
        Log(LOG_LEVEL_ERROR) << "cannot append transaction to txpool because it isn't valid";
        return false;
    }

    if (this->isTxInputPresent(&transactionForNetwork)) {
        Log(LOG_LEVEL_WARNING)
                << "cannot append transaction to txpool because one of it's input has another transaction pending";

        if(transactionError != nullptr) {
            transactionError->setErrorCode(001);
            transactionError->setErrorMessage("Cannot send the transaction, another one is still pending confirmation");
        }
        return false;
    }

    transaction.setTimestamp(Time::getCurrentTimestamp());
    transactionForNetwork.setTransaction(transaction);

    transactionListLock.lock();
    this->transactionList.insert(
            std::pair<std::string, TransactionForNetwork>(
                    Hexdump::vectorToHexString(TransactionHelper::getTxId(&transaction)),
                    transactionForNetwork
            )
    );
    transactionListLock.unlock();

    if (TransactionHelper::isRegisterPassport(&transaction)) {
        X509* x509 = X509Helper::vectorToCert(transactionForNetwork.getAdditionalPayload());
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction, x509);
        X509_free(x509);

        txInputsLock.lock();
        this->txInputs.insert(std::make_pair(Hexdump::vectorToHexString(passportHash), transaction.getTxIns().front()));
        txInputsLock.unlock();
    } else {
        for (TxIn txIn: transaction.getTxIns()) {
            txInputsLock.lock();
            this->txInputs.insert(std::make_pair(Hexdump::vectorToHexString(txIn.getInAddress()), txIn));
            txInputsLock.unlock();
        }
    }

    if (broadcast) {
        std::thread t1(&Network::broadCastTransaction, transactionForNetwork);
        t1.detach();
    }

    return true;
}

void TxPool::appendTransactionsFromBlock(Block* block) {
    for(auto tx : block->getTransactions()) {
        TransactionForNetwork transactionForNetwork;
        transactionForNetwork.setTransaction(tx);
        this->appendTransaction(transactionForNetwork, NO_BROADCAST_TRANSACTION, nullptr);
    }

    for(auto tx : block->getHeader()->getVotes()) {
        TransactionForNetwork transactionForNetwork;
        transactionForNetwork.setTransaction(tx);
        this->appendTransaction(transactionForNetwork, NO_BROADCAST_TRANSACTION, nullptr);
    }
}

uint32_t TxPool::getTxCount() {
    transactionListLock.lock();
    uint32_t txCount = (uint32_t)this->transactionList.size();
    transactionListLock.unlock();

    return txCount;
}

TransactionForNetwork* TxPool::popTransaction() {
    if(getTxCount() == 0) {
        return nullptr;
    }
    transactionListLock.lock();
    auto tb = this->transactionList.begin();
    TransactionForNetwork* rval = new TransactionForNetwork();
    *rval = tb->second;
    this->transactionList.erase(tb->first);
    transactionListLock.unlock();

    Transaction transaction = rval->getTransaction();
    if(TransactionHelper::isRegisterPassport(&transaction)) {
        std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction, X509Helper::vectorToCert(rval->getAdditionalPayload()));

        txInputsLock.lock();
        this->txInputs.erase(Hexdump::vectorToHexString(passportHash));
        txInputsLock.unlock();
    } else {
        for (TxIn txIn: rval->getTransaction().getTxIns()) {
            txInputsLock.lock();
            this->txInputs.erase(Hexdump::vectorToHexString(txIn.getInAddress()));
            txInputsLock.unlock();
        }
    }

    return rval;
}

// removes transactions that have become invalid,
// re-broadcasts transactions after 10 minutes if they haven't been inserted into a block
void TxPool::cleanTxPool() {
    Log(LOG_LEVEL_INFO) << "Going to clean the transaction pool";
    transactionListLock.lock();

    std::vector<std::vector<unsigned char>> transactionsToRemoveIDs;
    for (std::unordered_map<std::string, TransactionForNetwork>::iterator transactionIt = this->transactionList.begin(); transactionIt != this->transactionList.end(); ++transactionIt)
    {
        // Transaction has become invalid so we remove it
        if(!TransactionVerify::verifyNetworkTx(&transactionIt->second, nullptr)) {
            Transaction transaction = transactionIt->second.getTransaction();
            transactionsToRemoveIDs.emplace_back(TransactionHelper::getTxId(&transaction));
            continue;
        }

        // Rebroadcast the transaction
        // This could be removed later when there will be more validators
        if(transactionIt->second.getTimestampLastBroadcasted() + 600 < Time::getCurrentTimestamp()) {
            std::thread t1(&Network::broadCastTransaction, transactionIt->second);
            t1.detach();
        }
    }
    transactionListLock.unlock();

    for(const std::vector<unsigned char>& txId : transactionsToRemoveIDs) {
        popTransaction(txId);
    }
}
