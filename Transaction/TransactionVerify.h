#ifndef UBICD_TRANSACTIONVERIFY_H
#define UBICD_TRANSACTIONVERIFY_H


#include "Transaction.h"
#include "TransactionError.h"
#include "../Block/BlockHeader.h"
#include "../CertStore/Cert.h"

class TransactionVerify {
public:
    static bool verifyNetworkTx(TransactionForNetwork* tx, TransactionError* transactionError);
    static bool verifyTx(Transaction* tx, uint8_t isInHeader,  BlockHeader* header, TransactionError* transactionError);
    static bool verifyRegisterPassportTx(Transaction* tx, uint32_t blockHeight, Cert* cert, TransactionError* transactionError);
};


#endif //UBICD_TRANSACTIONVERIFY_H
