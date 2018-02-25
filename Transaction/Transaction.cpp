
#include "Transaction.h"
#include "../Tools/Log.h"
#include "../CertStore/CertStore.h"

void Transaction::addTxIn(TxIn txIn) {
    this->txIns.emplace_back(txIn);
}

void Transaction::setTxIns(std::vector<TxIn> txIns) {
    this->txIns = txIns;
}

std::vector <TxIn> Transaction::getTxIns() {
    return this->txIns;
}

void Transaction::addTxOut(TxOut txOut) {
    this->txOuts.emplace_back(txOut);
}

void Transaction::setTxOuts(std::vector<TxOut> txOuts) {
    this->txOuts = txOuts;
}

std::vector<TxOut> Transaction::getTxOuts() {
    return this->txOuts;
}

uint8_t Transaction::getNetwork() const {
    return network;
}

void Transaction::setNetwork(uint8_t network) {
    Transaction::network = network;
}
