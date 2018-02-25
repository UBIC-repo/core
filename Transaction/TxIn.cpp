
#include "TxIn.h"

UAmount TxIn::getAmount() {
    return amount;
}

void TxIn::setAmount(const UAmount &amount) {
    TxIn::amount = amount;
}

std::vector<unsigned char> TxIn::getInAddress() {
    return inAddress;
}

void TxIn::setInAddress(std::vector<unsigned char> inAddress) {
    this->inAddress = inAddress;
}

uint32_t TxIn::getNonce() {
    return nonce;
}

void TxIn::setNonce(uint32_t nonce) {
    this->nonce = nonce;
}

UScript TxIn::getScript() {
    return script;
}

void TxIn::setScript(UScript script) {
    this->script = script;
}
