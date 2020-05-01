
#ifndef TX_TRANSACTIONHELPER_H
#define TX_TRANSACTIONHELPER_H

#include <vector>
#include <list>
#include "TxIn.h"
#include "TxOut.h"
#include "../Block/BlockHeader.h"
#include "../Scripts/DeactivateCertificateScript.h"
#include "../CertStore/Cert.h"
#include "TransactionError.h"

class TransactionHelper {
public:
    static bool verifyNonce(std::vector<unsigned char> inAddress, uint32_t nonce);
    static uint32_t getNonce(std::vector<unsigned char> inAddress);
    static std::vector<unsigned char> getDeactivateCertificateScriptId(DeactivateCertificateScript deactivateCertificateScript);
    static std::vector<unsigned char> getTxId(Transaction* tx);
    static std::vector<unsigned char> getTxHash(Transaction* tx);
    static uint32_t getTxSize(Transaction* tx);
    static std::vector<unsigned char> getPassportHash(Transaction* tx, X509* x509);
    static bool isVote(Transaction* tx);
    static bool isRegisterPassport(Transaction* tx);
    static UAmount calculateMinimumFee(Transaction* transaction, BlockHeader* header);
    static UAmount calculateMinimumFee(size_t txSize, BlockHeader* header);
};


#endif //TX_TRANSACTIONHELPER_H
