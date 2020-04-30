
#ifndef TX_TRANSACTIONHELPER_H
#define TX_TRANSACTIONHELPER_H

#include <vector>
#include <list>
#include "TxIn.h"
#include "TxOut.h"
#include "../BlockHeader.h"
#include "../Scripts/DeactivateCertificateScript.h"
#include "../CertStore/Cert.h"

class TransactionHelper {
private:
    static bool verifyNonce(std::vector<unsigned char> inAddress, uint32_t nonce);
    static uint32_t getNonce(std::vector<unsigned char> inAddress);
public:
    static std::vector<unsigned char> getDeactivateCertificateScriptId(DeactivateCertificateScript deactivateCertificateScript);
    static std::vector<unsigned char> getTxId(Transaction* tx);
    static std::vector<unsigned char> getTxHash(Transaction* tx);
    static uint32_t getTxSize(Transaction* tx);
    static std::vector<unsigned char> getPassportHash(Transaction* tx, X509* x509);
    static bool isVote(Transaction* tx);
    static bool isRegisterPassport(Transaction* tx);
    static bool verifyNetworkTx(TransactionForNetwork* tx);
    static bool verifyTx(Transaction* tx, uint8_t isInHeader,  BlockHeader* header);
    static bool verifyRegisterPassportTx(Transaction* tx, uint32_t blockHeight, Cert* cert);
    static bool applyTransaction(Transaction* tx, BlockHeader* blockHeader);
    static bool undoTransaction(Transaction* tx, BlockHeader* blockHeader);
    static UAmount calculateMinimumFee(Transaction* transaction, BlockHeader* header);
    static UAmount calculateMinimumFee(size_t txSize, BlockHeader* header);
};


#endif //TX_TRANSACTIONHELPER_H
