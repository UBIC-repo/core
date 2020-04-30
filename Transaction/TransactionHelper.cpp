#include "TransactionHelper.h"
#include "../streams.h"
#include "../Tools/Log.h"
#include "../Crypto/Hash256.h"
#include "../NtpEsk/NtpEskSignatureVerificationObject.h"
#include "../CertStore/CertStore.h"
#include "../AddressStore.h"
#include "../Crypto/VerifySignature.h"
#include "../Chain.h"
#include "../NtpRsk/NtpRsk.h"
#include "../Time.h"
#include "../Scripts/AddCertificateScript.h"
#include "../CertStore/CertHelper.h"

bool TransactionHelper::verifyNonce(std::vector<unsigned char> inAddress, uint32_t nonce) {
    AddressStore& addressStore = AddressStore::Instance();
    AddressForStore addressForStore = addressStore.getAddressFromStore(inAddress);

    return addressForStore.getNonce() == nonce;
}

uint32_t TransactionHelper::getNonce(std::vector<unsigned char> inAddress) {
    AddressStore& addressStore = AddressStore::Instance();
    AddressForStore addressForStore = addressStore.getAddressFromStore(inAddress);

    return addressForStore.getNonce();
}

std::vector<unsigned char> TransactionHelper::getDeactivateCertificateScriptId(DeactivateCertificateScript deactivateCertificateScript) {
    deactivateCertificateScript.rootCertSignature = std::vector<unsigned char>();

    CDataStream s(SER_DISK, 1);
    s << deactivateCertificateScript;

    return std::vector<unsigned char>(s.data(), s.data() + s.size());
}

std::vector<unsigned char> TransactionHelper::getTxId(Transaction* tx) {
    Transaction txClone = *tx;
    UScript emptyScript;
    std::vector<unsigned char> emptyVector = std::vector<unsigned char>();
    emptyScript.setScriptType(SCRIPT_EMPTY);
    emptyScript.setScript(emptyVector);

    std::vector<TxIn> cleanedTxIns;
    std::vector<TxIn> txIns = tx->getTxIns();
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        txIn->setScript(emptyScript);
        cleanedTxIns.emplace_back(*txIn);
    }

    txClone.setTxIns(cleanedTxIns);

    CDataStream s(SER_DISK, 1);
    s << txClone;

    std::vector<unsigned char> txId = Hash256::hash256(std::vector<unsigned char>(s.data(), s.data() + s.size()));

    return txId;
}

std::vector<unsigned char> TransactionHelper::getTxHash(Transaction* tx) {
    CDataStream s(SER_DISK, 1);
    s << *tx;

    std::vector<unsigned char> txHash = Hash256::hash256(std::vector<unsigned char>(s.data(), s.data() + s.size()));

    return txHash;
}

uint32_t TransactionHelper::getTxSize(Transaction* tx) {
    CDataStream s(SER_DISK, 1);
    s << *tx;

    return (uint32_t)s.size();
}

std::vector<unsigned char> TransactionHelper::getPassportHash(Transaction* tx, X509* x509) {
    CDataStream srpScript(SER_DISK, 1);
    UScript script = tx->getTxIns().front().getScript();
    srpScript.write((char *) script.getScript().data(), script.getScript().size());

    if((uint32_t)script.getScript().at(0) % 2 == 0) {
        // is NtpRsk
        NtpRskSignatureVerificationObject ntpRskSignatureVerificationObject;

        try {
            srpScript >> ntpRskSignatureVerificationObject;
        } catch (const std::exception& e) {
            Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";
            return std::vector<unsigned char>();
        }

        return ECCtools::bnToVector(ntpRskSignatureVerificationObject.getM());
    } else {
        // is NtpEsk

        NtpEskSignatureVerificationObject ntpEskSignatureVerificationObject;
        EC_KEY *ecKey;
        if(x509 != nullptr) {
            ecKey = EVP_PKEY_get1_EC_KEY(X509_get_pubkey(x509));
        } else {
            CertStore &certStore = CertStore::Instance();
            Cert *cert = certStore.getDscCertWithCertId(tx->getTxIns().front().getInAddress());
            ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());
        }
        ntpEskSignatureVerificationObject.setCurveParams(EC_KEY_get0_group(ecKey));
        try {
            srpScript >> ntpEskSignatureVerificationObject;
        } catch (const std::exception& e) {
            Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";
            return std::vector<unsigned char>();
        }
        return ntpEskSignatureVerificationObject.getMessageHash();
    }
}

bool TransactionHelper::isVote(Transaction* tx) {

    if(tx->getTxIns().size() != 1 || tx->getTxOuts().size() != 1) {
        return false;
    }

    if(tx->getTxIns().front().getScript().getScriptType() != SCRIPT_VOTE) {
        return false;
    }

    if(tx->getTxOuts().front().getScript().getScriptType() != SCRIPT_VOTE) {
        return false;
    }

    return true;
}

bool TransactionHelper::isRegisterPassport(Transaction* tx) {

    if(tx->getTxIns().size() != 1 || tx->getTxOuts().size() != 1) {
        return false;
    }

    if(tx->getTxIns().front().getScript().getScriptType() != SCRIPT_REGISTER_PASSPORT) {
        return false;
    }

    if(tx->getTxOuts().front().getScript().getScriptType() != SCRIPT_PKH) {
        return false;
    }

    return true;
}

/**
 * The transaction fee depends on the size of the transaction and the current UBI payout
 * Current assumption is UBI payout should allow every one to send about ~1kb of data a day
 * As consequence minimum txfee for 1 Block a minute is:
 * (byte)txSize * payout = 1,440 bytes
 * It is important to keep in mind that the txFees goes back as UBI!
 * Passport registration, certification addition/removal are exempt of fees
 *
 * Note that it is only possible to pay the txFee in one unique currency
 *
 * @param transaction
 * @param header
 * @return UAmount
 */
UAmount TransactionHelper::calculateMinimumFee(Transaction* transaction, BlockHeader* header) {

    CDataStream s(SER_DISK, 1);
    s << *transaction;

    return calculateMinimumFee(s.size(), header);
}

UAmount TransactionHelper::calculateMinimumFee(size_t txSize, BlockHeader* header) {
    //@TODO: check
    UAmount rAmount;
    if(header == nullptr) {
        return rAmount;
    }

    UAmount totalPayout = BlockHelper::getTotalPayout(header->getBlockHeight());
    UAmount32 receiverCounts = header->getUbiReceiverCount();

    for(auto& payout : totalPayout.map) {
        uint32_t receiverCount = receiverCounts.map.at(payout.first);
        // to avoid too huge txFees during the early stage and division by zero
        if(receiverCount < 1000) {
            receiverCount = 1000;
        }
        payout.second = (uint64_t) payout.second / receiverCount;
        if(payout.second == 0) {
            payout.second = 1;
        }
    }

    for (std::map<uint8_t, CAmount>::const_iterator it(totalPayout.map.begin()); it != totalPayout.map.end(); ++it) {
        rAmount.map[it->first] = (uint64_t) it->second * txSize * TXFEE_FACTOR;
    }

    return rAmount;
}
