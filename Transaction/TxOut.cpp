
#include "TxOut.h"

UAmount TxOut::getAmount() {
    return amount;
}

void TxOut::setAmount(UAmount &amount) {
    TxOut::amount = amount;
}

UScript TxOut::getScript() {
    return script;
}

void TxOut::setScript(UScript script) {
    TxOut::script = script;
}