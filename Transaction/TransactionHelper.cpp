
#include "TransactionHelper.h"
#include "../streams.h"
#include "../Tools/Log.h"
#include "../Crypto/Hash256.h"
#include "../NtpEsk/NtpEskSignatureVerificationObject.h"
#include "../CertStore/CertStore.h"
#include "../AddressStore.h"
#include "../DB/DB.h"
#include "../Crypto/VerifySignature.h"
#include "../DSCAttachedPassportCounter.h"
#include "../Chain.h"
#include "../AddressHelper.h"
#include "../Wallet.h"
#include "../NtpRsk/NtpRsk.h"
#include "../Consensus/VoteStore.h"
#include "../Time.h"
#include "../Fixes.h"
#include "../Scripts/PkhInScript.h"
#include "../Scripts/AddCertificateScript.h"
#include "../Scripts/NtpskAlreadyUsedScript.h"
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

bool TransactionHelper::verifyRegisterPassportTx(Transaction* tx, uint32_t blockHeight, Cert* cert) {

    if(!TransactionHelper::isRegisterPassport(tx)) {
        Log(LOG_LEVEL_ERROR) << "SCRIPT_REGISTER_PASSPORT is not an valid REGISTER_PASSPORT transaction";
        return false;
    }

    TxIn txIn = tx->getTxIns().front();
    UScript script = txIn.getScript();

    if(txIn.getNonce() != 0) {
        Log(LOG_LEVEL_ERROR) << "for SCRIPT_REGISTER_PASSPORT nonce has always to be 0";
        return false;
    }

    CertStore& certStore = CertStore::Instance();
    if(cert == nullptr) {
        cert = certStore.getDscCertWithCertId(txIn.getInAddress());
        if(cert == nullptr) {
            Log(LOG_LEVEL_ERROR) << "CertStore returned no DSC " << txIn.getInAddress() << " match for the NtpEsk";
            return false;
        }
    }

    if(cert->getCurrencyId() == 0) {
        Log(LOG_LEVEL_ERROR) << "Cannot register passport because currency id is 0";
        return false;
    }

    if(!cert->isCertAtive()) {
        Log(LOG_LEVEL_ERROR) << "Cert is not active " << txIn.getInAddress();
        return false;
    }

    std::vector<unsigned char> txId = TransactionHelper::getTxId(tx);
    CDataStream srpScript(SER_DISK, 1);
    srpScript.write((char *) script.getScript().data(), script.getScript().size());
    uint32_t ntpskVersion = (uint32_t) script.getScript().at(0);

    if(blockHeight >= UPGRADE_0_2_0_BLOCK_HEIGHT && ntpskVersion < 3) {
        Log(LOG_LEVEL_ERROR) << "After block "
                             << UPGRADE_0_2_0_BLOCK_HEIGHT
                             << " only ntpsk proofs with version numbers superior to 3 are accepted";
        return false;
    }

    if(ntpskVersion % 2 == 0) {
        // is NtpRsk

        EVP_PKEY *pkey = X509_get0_pubkey(cert->getX509());
        RSA *rsa = EVP_PKEY_get1_RSA(pkey);

        const BIGNUM *n = BN_new();
        const BIGNUM *e = BN_new();
        RSA_get0_key(rsa, &n, &e, nullptr);

        NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();

        try {
            srpScript >> *ntpRskSignatureVerificationObject;
        } catch (const std::exception &e) {
            Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";
            return false;
        }

        ntpRskSignatureVerificationObject->setN(n);
        ntpRskSignatureVerificationObject->setE(e);
        ntpRskSignatureVerificationObject->setNm(ECCtools::vectorToBn(txId));

        std::vector<unsigned char> em = ECCtools::bnToVector(ntpRskSignatureVerificationObject->getPaddedM());

        Log(LOG_LEVEL_INFO) << "going to verify padding on: " << em;

        //
        //
        // Begin of padding verification hack
        //
        //

        bool verifiedPadding = false;

        std::vector<unsigned char> em2;
        em2.emplace_back((unsigned char) 0x00);
        em2.insert(em2.end(), em.begin(), em.end());

        std::string asn1RSAWITHSHA256hex;
        asn1RSAWITHSHA256hex = "3031300d060960864801650304020105000420"; // only fits for RSA2048 signatures

        std::vector<unsigned char> asn1RSAWITHSHA256;
        asn1RSAWITHSHA256 = Hexdump::hexStringToVector(asn1RSAWITHSHA256hex);

        asn1RSAWITHSHA256.insert(asn1RSAWITHSHA256.end(), txId.begin(), txId.end());

        if (RSA_padding_check_PKCS1_type_1(asn1RSAWITHSHA256.data(), (uint32_t) asn1RSAWITHSHA256.size(), em2.data(),
                                           (uint32_t) em2.size(), (uint32_t) em2.size()) >= 0) {
            Log(LOG_LEVEL_INFO) << "Register passport: PKCS1_type_1 verified with SHA256 ASN1";
            verifiedPadding = true;
        }

        if (!verifiedPadding) {
            if (RSA_verify_PKCS1_PSS(rsa, asn1RSAWITHSHA256.data(), EVP_sha256(), em2.data(), (uint32_t) em2.size()) >=
                0) {
                Log(LOG_LEVEL_INFO) << "Register passport: PKCS1_PSS verified with SHA256 ASN1";
                verifiedPadding = true;
            }
        }

        //@TODO 4096 bit RSA padding

        if (!verifiedPadding) {
            Log(LOG_LEVEL_ERROR) << "Failed to verify padding";
            Log(LOG_LEVEL_INFO) << "em : " << em;
            Log(LOG_LEVEL_INFO) << "em2 : " << em2;
            delete ntpRskSignatureVerificationObject;
            return false;
        }

        //
        //
        // end of padding verification hack
        //
        //

        // verify signed payload
        if (ntpskVersion >= 3) {
            unsigned char digest[128];
            unsigned int digestLength;
            EVP_MD_CTX *mdctx;
            mdctx = EVP_MD_CTX_create();

            EVP_DigestInit_ex(mdctx, EVP_get_digestbynid(ntpRskSignatureVerificationObject->getMdAlg()), NULL);
            EVP_DigestUpdate(mdctx, ntpRskSignatureVerificationObject->getSignedPayload().data(),
                             ntpRskSignatureVerificationObject->getSignedPayload().size());
            EVP_DigestFinal_ex(mdctx, digest, &digestLength);

            EVP_MD_CTX_destroy(mdctx);
            std::vector<unsigned char> passportHash = ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM());
            if (memcmp(digest, passportHash.data(), digestLength) != 0) {
                Log(LOG_LEVEL_ERROR) << "Signed payload hash mismatch";
                delete ntpRskSignatureVerificationObject;
                return false;
            }
        }

        // verify proof not already used
        DB& db = DB::Instance();
        if(db.isInDB(DB_NTPSK_ALREADY_USED, ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()))) {
            Log(LOG_LEVEL_ERROR) << "NtpRsk " << ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()) << " already used";
            delete ntpRskSignatureVerificationObject;
            return false;
        }

        // Verify NtpEsk proof itself
        if(!NtpRsk::verifyNtpRsk(ntpRskSignatureVerificationObject)) {
            Log(LOG_LEVEL_ERROR) << "NtpRsk failed";
            delete ntpRskSignatureVerificationObject;
            return false;
        }
        delete ntpRskSignatureVerificationObject;

    } else {
        // is NtpEsk

        //set PubKey and curve params from Cert store
        EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());

        NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = new NtpEskSignatureVerificationObject();
        ntpEskSignatureVerificationObject->setPubKey(EC_KEY_get0_public_key(ecKey));
        ntpEskSignatureVerificationObject->setCurveParams(EC_KEY_get0_group(ecKey));
        ntpEskSignatureVerificationObject->setNewMessageHash(txId);

        try {
            srpScript >> *ntpEskSignatureVerificationObject;
        } catch (const std::exception& e) {
            Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";
            return false;
        }

        // verify signed payload
        if (ntpskVersion >= 3) {
            unsigned char digest[128];
            unsigned int digestLength;
            EVP_MD_CTX *mdctx;
            mdctx = EVP_MD_CTX_create();

            EVP_DigestInit_ex(mdctx, EVP_get_digestbynid(ntpEskSignatureVerificationObject->getMdAlg()), NULL);
            EVP_DigestUpdate(mdctx, ntpEskSignatureVerificationObject->getSignedPayload().data(),
                             ntpEskSignatureVerificationObject->getSignedPayload().size());
            EVP_DigestFinal_ex(mdctx, digest, &digestLength);

            EVP_MD_CTX_destroy(mdctx);
            if (memcmp(digest, ntpEskSignatureVerificationObject->getMessageHash().data(), digestLength) != 0) {
                Log(LOG_LEVEL_ERROR) << "Signed payload hash mismatch";
                delete ntpEskSignatureVerificationObject;
                return false;
            }
        }

        // verify proof not already used
        DB &db = DB::Instance();
        if (db.isInDB(DB_NTPSK_ALREADY_USED, ntpEskSignatureVerificationObject->getMessageHash())) {
            Log(LOG_LEVEL_ERROR) << "NtpEsk " << ntpEskSignatureVerificationObject->getMessageHash()
                                 << " already used";
            delete ntpEskSignatureVerificationObject;
            return false;
        }

        // Verify NtpEsk proof itself
        if(!NtpEsk::verifyNtpEsk(ntpEskSignatureVerificationObject)) {
            Log(LOG_LEVEL_ERROR) << "NtpEsk failed";
            delete ntpEskSignatureVerificationObject;
            return false;
        }

        delete ntpEskSignatureVerificationObject;
    }

    return true;
}

bool TransactionHelper::verifyNetworkTx(TransactionForNetwork* txForNetwork) {

    if(txForNetwork->getAdditionalPayload().size() > MAXIMUM_TRANSACTION_PAYLOAD_SIZE) {
        return false;
    }

    Transaction tx = txForNetwork->getTransaction();
    Chain& chain = Chain::Instance();

    BlockHeader* bestHeader = chain.getBestBlockHeader();

    if(bestHeader == nullptr) {
        // something is wrong with our node, we can not verify the transaction
        return false;
    }

    if(verifyTx(&tx, IGNORE_IS_IN_HEADER, bestHeader)) {
        delete bestHeader;
        return true;
    }
    delete bestHeader;

    if(isRegisterPassport(&tx) && txForNetwork->getAdditionalPayloadType() == PAYLOAD_TYPE_DSC_CERTIFICATE) {
        // the passport transaction is a special case
        // It requires to take into account the additionalPayload field

        std::vector<unsigned char> payload = txForNetwork->getAdditionalPayload();
        BIO *certbio = BIO_new_mem_buf((void*)payload.data(),
                                       (int)payload.size());

        X509 *x509 = d2i_X509_bio(certbio, nullptr);

        if(x509 == nullptr) {
            BIO_free(certbio);
            return false;
        }

        uint8_t currencyId = CertHelper::getCurrencyIdForCert(x509);
        if(currencyId == 0) {
            X509_free(x509);
            BIO_free(certbio);
            return false;
        }

        uint64_t expiration = CertHelper::calculateDSCExpirationDateForCert(x509);
        if(expiration < Time::getCurrentTimestamp() + 600) { //expired or going to expire very soon
            X509_free(x509);
            BIO_free(certbio);
            return false;
        }

        Chain& chain = Chain::Instance();
        CertStore& certStore = CertStore::Instance();

        Cert cert;
        cert.setCurrencyId(currencyId);
        cert.setExpirationDate(expiration);
        cert.setX509(x509);
        cert.appendStatusList(std::pair<uint32_t, bool>(chain.getCurrentBlockchainHeight(), true));

        if(certStore.getDscCertWithCertId(cert.getId()) != nullptr) {
            // This case was already tested previously and if we are here it failed
            X509_free(x509);
            BIO_free(certbio);
            return false;
        }

        if(!certStore.isCertSignedByCSCA(&cert, chain.getCurrentBlockchainHeight())) {
            X509_free(x509);
            BIO_free(certbio);
            return false;
        }

        bool verified = verifyRegisterPassportTx(&tx, chain.getCurrentBlockchainHeight(), &cert);

        X509_free(x509);
        BIO_free(certbio);

        return verified;
    }

    return false;
}

/**
 * @param tx
 * @param isInHeader // Votes are in the header, payments in the body
 * @param header
 * @return bool
 */
bool TransactionHelper::verifyTx(Transaction* tx, uint8_t isInHeader, BlockHeader* header) {

    Chain& chain = Chain::Instance();
    BlockHeader* bestHeader = chain.getBestBlockHeader();

    if(TransactionHelper::getTxSize(tx) > TRANSACTION_SIZE_MAX) {
        Log(LOG_LEVEL_ERROR) << "transaction is of size"
                             << TransactionHelper::getTxSize(tx)
                             << " but maximum allowed transaction size is "
                             << TRANSACTION_SIZE_MAX;
        return false;
    }

    AddressStore& addressStore = AddressStore::Instance();

    uint32_t txInputCount = tx->getTxIns().size();
    uint32_t txOutputCount = tx->getTxOuts().size();

    if(tx->getNetwork() != NET_CURRENT) {
        Log(LOG_LEVEL_ERROR) << "transaction with wrong network id " << tx->getNetwork();
        return false;
    }

    UAmount totalInAmount;
    UAmount totalOutAmount;
    UAmount addressAvailableAmount;
    std::vector<TxIn> txIns = tx->getTxIns();
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        UAmount inAmount = txIn->getAmount();
        if(!UAmountHelper::isValidAmount(inAmount)) {
            Log(LOG_LEVEL_ERROR) << "invalid inAmount: "
                                 << inAmount;
            return false;
        }
        totalInAmount += inAmount;
        AddressForStore addressForStore = addressStore.getAddressFromStore(txIn->getInAddress());
        addressAvailableAmount += AddressHelper::getAmountWithUBI(&addressForStore);
    }

    if(!(addressAvailableAmount >= totalInAmount)) {
        Log(LOG_LEVEL_ERROR) << "Transaction "
                             << TransactionHelper::getTxId(tx)
                             << " is trying to spend more than it's balance "
                             << totalInAmount
                             << " > "
                             << addressAvailableAmount;
        return false;
    }

    std::vector<TxOut> txOuts = tx->getTxOuts();
    for (std::vector<TxOut>::iterator txOut = txOuts.begin(); txOut != txOuts.end(); ++txOut) {
        UAmount outAmount = txOut->getAmount();
        if(!UAmountHelper::isValidAmount(outAmount)) {
            Log(LOG_LEVEL_ERROR) << "invalid outAmount: "
                                 << outAmount;
            return false;
        }
        totalOutAmount += outAmount;

        switch(txOut->getScript().getScriptType()) {
            case SCRIPT_LINK: {
                //@TODO verify LINK exists
                Log(LOG_LEVEL_ERROR) << "SCRIPT_LINK deactivated for now";
                return false;
            }
            case SCRIPT_VOTE: {
                break;
            }
            case SCRIPT_PKH: {
                break;
            }
            default: {
                Log(LOG_LEVEL_CRITICAL_ERROR) << "Unknown TxOut script type: " << txOut->getScript().getScriptType();
                return false;
            }
        }
    }

    if(!(totalInAmount >= totalOutAmount)) {
        Log(LOG_LEVEL_ERROR) << "outAmount > inAmount " << " inAmount : " << totalInAmount << " outAmount : " << totalOutAmount;
        return false;
    }

    std::vector<unsigned char> txId = TransactionHelper::getTxId(tx);
    bool needToPayFee = true;
    bool isVote = false;

    // verify all inputs script
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        UScript script = txIn->getScript();
        switch (script.getScriptType()) {

            case SCRIPT_LINK: {
                if(!TransactionHelper::verifyNonce(txIn->getInAddress(), txIn->getNonce())) {
                    Log(LOG_LEVEL_ERROR) << "wrong nonce " << txIn->getNonce()
                                         << " expected "
                                         << TransactionHelper::getNonce(txIn->getInAddress())
                                         << " for address: "
                                         << txIn->getInAddress();
                    return false;
                }

                Log(LOG_LEVEL_ERROR) << "SCRIPT_LINK deactivated for now";
                return false;
                break;
            }
            case SCRIPT_PKH: {
                if(!TransactionHelper::verifyNonce(txIn->getInAddress(), txIn->getNonce())) {
                    Log(LOG_LEVEL_ERROR) << "wrong nonce " << txIn->getNonce()
                                         << " expected "
                                         << TransactionHelper::getNonce(txIn->getInAddress())
                                         << " for address: "
                                         << txIn->getInAddress();
                    return false;
                }
                PkhInScript pkhInScript;

                try {
                    CDataStream pkhscript(SER_DISK, 1);
                    pkhscript.write((char *) script.getScript().data(), script.getScript().size());
                    pkhscript >> pkhInScript;
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_PKH payload";
                    return false;
                }

                //verify signature
                switch(pkhInScript.getVersion()) {
                    case PKH_SECP256K1_VERSION: {
                        Address recoveredAddress = Wallet::addressFromPublicKey(
                                pkhInScript.publicKey
                        );

                        std::vector<unsigned char> recoveredAddressVector = AddressHelper::addressLinkFromScript(recoveredAddress.getScript());

                        if(recoveredAddressVector != txIn->getInAddress()) {
                            Log(LOG_LEVEL_ERROR) << "recoveredAddress: "
                                                 << recoveredAddressVector
                                                 << " doesn't equal inAddress: "
                                                 << txIn->getInAddress()
                                                 << " for " << txId;
                            return false;
                        }

                        if(!VerifySignature::verify(txId, pkhInScript.signature, pkhInScript.publicKey)) {
                            Log(LOG_LEVEL_ERROR) << "Signature verification failed for transaction: " << txId
                                                 << " Signature: "
                                                 << pkhInScript.signature
                                                 << " Public key: "
                                                 << pkhInScript.publicKey;
                            return false;
                        }
                        break;
                    }
                    default: {
                        Log(LOG_LEVEL_ERROR) << "error: Unknown pkhInScript version " << pkhInScript.getVersion();
                        return false;
                    }
                }

                break;
            }
            case SCRIPT_REGISTER_PASSPORT: {
                if(!TransactionHelper::verifyRegisterPassportTx(tx, header->getBlockHeight(), nullptr)) {
                    Log(LOG_LEVEL_INFO) << "Failed to verify register passport transaction";
                    return false;
                }

                needToPayFee = false;
                break;
            }
            case SCRIPT_ADD_CERTIFICATE: {
                AddCertificateScript addCertificateScript;

                try {
                    CDataStream acScript(SER_DISK, 1);
                    acScript.write((char *) script.getScript().data(), script.getScript().size());
                    acScript >> addCertificateScript;
                    acScript.clear();
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_ADD_CERTIFICATE payload";
                    return false;
                }

                Cert *cert = new Cert();

                BIO *certbio = BIO_new_mem_buf(addCertificateScript.certificate.data(), (int)addCertificateScript.certificate.size());
                X509 *x509 = d2i_X509_bio(certbio, NULL);

                // if it's an RSA certificate verify that the exponent >= 65537
                EVP_PKEY* pkey = X509_get0_pubkey(x509);
                RSA* rsa = EVP_PKEY_get1_RSA(pkey);

                if(rsa != nullptr) {
                    const BIGNUM* exponent = BN_new();
                    BIGNUM* minExponent = BN_new();
                    RSA_get0_key(rsa, nullptr, &exponent, nullptr);
                    BN_dec2bn(&minExponent, "65537");

                    if (addCertificateScript.isDSC() && BN_cmp(exponent, minExponent) == -1) {
                        Log(LOG_LEVEL_ERROR) << "SCRIPT_ADD_CERTIFICATE failed because RSA exponent is too small minimum required is 65537";
                        return false;
                    }
                }

                uint32_t currentHeaderTimeStamp = 0;
                if(header != nullptr) {
                    currentHeaderTimeStamp = header->getTimestamp();
                }

                if(addCertificateScript.expirationDate < currentHeaderTimeStamp) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_ADD_CERTIFICATE failed because it is expired, addCertificateScript.expirationDate:"
                                         << addCertificateScript.expirationDate ;
                    return false;
                }

                cert->setX509(x509);
                cert->setNonce(txIn->getNonce());
                cert->setRootSignature(addCertificateScript.rootSignature);
                cert->setExpirationDate(addCertificateScript.expirationDate);
                cert->setCurrencyId(addCertificateScript.currency);

                if(txIn->getInAddress() != cert->getId()) {
                    Log(LOG_LEVEL_ERROR) << "txIn->getInAddress() " << txIn->getInAddress()
                                         << " and cert->getId() " << cert->getId() << " mismatch";
                    return false;
                }

                CertStore& certStore = CertStore::Instance();

                if(addCertificateScript.isCSCA()) {
                    if(!certStore.verifyAddCSCA(cert)) {
                        return false;
                    }
                } else if(addCertificateScript.isDSC()) {
                    if(!certStore.verifyAddDSC(cert, header->getBlockHeight())) {
                        return false;
                    }
                }

                if(addCertificateScript.type == TYPE_CSCA && !certStore.isCertSignedByUBICrootCert(cert, true, addCertificateScript.type)) {
                    Log(LOG_LEVEL_ERROR) << "cert: " << cert->getId() << " is not signed by UBIC root Cert";
                    return false;
                }

                if(addCertificateScript.isCSCA()) {
                    cert = certStore.getCscaCertWithCertId(txIn->getInAddress());
                } else if(addCertificateScript.isDSC()) {
                    if(!certStore.isCertSignedByCSCA(cert, chain.getCurrentBlockchainHeight())) {
                        Log(LOG_LEVEL_ERROR) << "DSC: " << cert->getId() << " is not signed by a CSCA";
                        return false;
                    }
                    cert = certStore.getDscCertWithCertId(txIn->getInAddress());
                } else {
                    Log(LOG_LEVEL_ERROR) << "unknown addCertificateScript type: " << addCertificateScript.type;
                    return false;
                }

                if(cert != nullptr) {
                    if(cert->getNonce() != txIn->getNonce()) {
                        Log(LOG_LEVEL_ERROR) << "add certificate, wrong nonce for certificate: " << cert->getId();
                        return false;
                    }

                    if(cert->isCertAtive()) {
                        Log(LOG_LEVEL_ERROR) << "cannot activate already active certificate: " << cert->getId();
                        return false;
                    }
                }

                X509_free(x509);
                BIO_free(certbio);
                delete cert;

                needToPayFee = false;
                break;
            }
            case SCRIPT_DEACTIVATE_CERTIFICATE: {
                DeactivateCertificateScript deactivateCertificateScript;

                try {
                    CDataStream dcScript(SER_DISK, 1);
                    dcScript.write((char *) script.getScript().data(), script.getScript().size());
                    dcScript >> deactivateCertificateScript;
                    deactivateCertificateScript.certificateId = txIn->getInAddress();
                    deactivateCertificateScript.nonce = txIn->getNonce();
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_DEACTIVATE_CERTIFICATE payload";
                    return false;
                }

                CertStore& certStore = CertStore::Instance();
                Cert* cert = new Cert();

                if(!deactivateCertificateScript.isDSC() && !deactivateCertificateScript.isCSCA()) {
                    Log(LOG_LEVEL_ERROR) << "Unkown certificate type: " << deactivateCertificateScript.type;
                    return false;
                }

                if(deactivateCertificateScript.isDSC()) {
                    cert = certStore.getDscCertWithCertId(deactivateCertificateScript.certificateId);
                } else if(deactivateCertificateScript.isCSCA()) {
                    cert = certStore.getCscaCertWithCertId(deactivateCertificateScript.certificateId);
                }

                if(deactivateCertificateScript.nonce != cert->getNonce()) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_DEACTIVATE_CERTIFICATE nonce mismatch";
                    return false;
                }

                if(!certStore.isSignedByUBICrootCert(
                        TransactionHelper::getDeactivateCertificateScriptId(deactivateCertificateScript),
                        deactivateCertificateScript.rootCertSignature)
                  ) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_DEACTIVATE_CERTIFICATE not signed by Root Cert";
                    return false;
                }

                needToPayFee = false;
                break;
            }
            case SCRIPT_VOTE: {
                std::vector<unsigned char> signature = txIn->getScript().getScript();

                if(!VerifySignature::verify(txId, signature, txIn->getInAddress())) {
                    Log(LOG_LEVEL_INFO) << "Signature : " << signature;
                    Log(LOG_LEVEL_INFO) << "getInAddress : " << txIn->getInAddress();
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_VOTE signature verification failed";
                    return false;
                }

                if(txInputCount != 1 || txOutputCount != 1) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_VOTE transactions are only allowed to have one input and one output";
                    return false;
                }

                Vote* vote = new Vote();

                try {
                    CDataStream dcScript(SER_DISK, 1);
                    dcScript.write((char *) tx->getTxOuts().front().getScript().getScript().data(), tx->getTxOuts().front().getScript().getScript().size());
                    dcScript >> *vote;
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_VOTE payload";
                    return false;
                }

                vote->setNonce(txIn->getNonce());
                vote->setFromPubKey(txIn->getInAddress());

                VoteStore& voteStore = VoteStore::Instance();
                if(!voteStore.verifyVote(vote)) {
                    Log(LOG_LEVEL_ERROR) << "voteStore.verifyVote failed";
                    return false;
                }

                isVote = true;
                needToPayFee = false;

                break;
            }
            default: {
                Log(LOG_LEVEL_CRITICAL_ERROR) << "unknown script type " << script.getScriptType();
                return false;
            }
        }
    }

    //verify fees
    //no fee verification for the genesis block or some kind of transactions
    if(bestHeader != nullptr && needToPayFee) {
        bool payedMinimumFee = false;
        UAmount payedFee = totalInAmount - totalOutAmount;
        UAmount calculatedMinimumFee = TransactionHelper::calculateMinimumFee(tx, bestHeader);

        for (std::map<uint8_t, CAmount>::const_iterator it(payedFee.map.begin()); it != payedFee.map.end(); ++it) {
            if(it->second >= calculatedMinimumFee.map[it->first]) {
                payedMinimumFee = true;
            }
        }

        if(!payedMinimumFee) {
            Log(LOG_LEVEL_ERROR) << "Transaction doesn't pay the minimum txFee"
                                 << " paid: "
                                 << payedFee
                                 << " required: "
                                 << calculatedMinimumFee;
            return false;
        }
    }

    // make sure votes are in the header and other transactions aren't
    if(isInHeader != IGNORE_IS_IN_HEADER) {
        if(isVote && isInHeader == IS_NOT_IN_HEADER) {
            Log(LOG_LEVEL_ERROR) << "Transaction is a vote but it isn't in the block header as expected";
            return false;
        } else if(!isVote && isInHeader == IS_IN_HEADER) {
            Log(LOG_LEVEL_ERROR) << "Transaction is not a vote but it is in the block header";
            return false;
        }
    }

    return true;
}

/**
 * Doesn't verify the Transaction itself, this should already have been done
 *
 * @param tx
 * @param blockHeader
 * @return bool
 */
bool TransactionHelper::applyTransaction(Transaction* tx, BlockHeader* blockHeader) {
    std::vector<TxIn> txIns = tx->getTxIns();
    AddressStore& addressStore = AddressStore::Instance();
    Wallet& wallet = Wallet::Instance();
    bool isRegisterPassportTx = false;
    bool isMine = false;
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        if(wallet.isMine(txIn->getInAddress())) {
            isMine = true;
        }
        switch(txIn->getScript().getScriptType()) {
            case SCRIPT_PKH: {
                addressStore.debitAddressToStore(txIn->getInAddress(), txIn->getAmount(), blockHeader, false);
                break;
            }
            case SCRIPT_REGISTER_PASSPORT: {
                UScript passportScript = txIn->getScript();

                CertStore& certStore = CertStore::Instance();
                DB &db = DB::Instance();

                CDataStream srpscript(SER_DISK, 1);
                srpscript.write((char *) passportScript.getScript().data(), passportScript.getScript().size());

                CDataStream nauscript(SER_DISK, 1);
                NtpskAlreadyUsedScript ntpskAlreadyUsedScript;
                ntpskAlreadyUsedScript.setAddress(tx->getTxOuts().front().getScript().getScript());
                ntpskAlreadyUsedScript.setDscID(txIn->getInAddress());

                if((uint32_t)passportScript.getScript().at(0) % 2 == 0) {
                    // is NtpRsk
                    NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();
                    srpscript >> *ntpRskSignatureVerificationObject;
                    nauscript << ntpskAlreadyUsedScript;

                    db.putInDB(DB_NTPSK_ALREADY_USED, ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()),
                               std::vector<unsigned char>(nauscript.data(), nauscript.data() + nauscript.size()));
                } else {
                    // is NtpEsk
                    Cert* cert = certStore.getDscCertWithCertId(txIn->getInAddress());
                    NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = new NtpEskSignatureVerificationObject();
                    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());
                    ntpEskSignatureVerificationObject->setCurveParams(EC_KEY_get0_group(ecKey));

                    srpscript >> *ntpEskSignatureVerificationObject;
                    nauscript << ntpskAlreadyUsedScript;
                    db.putInDB(DB_NTPSK_ALREADY_USED, ntpEskSignatureVerificationObject->getMessageHash(),
                               std::vector<unsigned char>(nauscript.data(), nauscript.data() + nauscript.size()));
                }
                srpscript.clear();

                DSCAttachedPassportCounter::increment(txIn->getInAddress());
                isRegisterPassportTx = true;
                break;
            }

            case SCRIPT_ADD_CERTIFICATE: {
                AddCertificateScript addCertificateScript;
                CDataStream s(SER_DISK, 1);
                s.write((char *) txIn->getScript().getScript().data(), txIn->getScript().getScript().size());
                s >> addCertificateScript;
                s.clear();

                CertStore &certStore = CertStore::Instance();

                Cert *cert = new Cert();

                BIO *certbio = BIO_new_mem_buf(addCertificateScript.certificate.data(), (int)addCertificateScript.certificate.size());
                X509 *x509 = d2i_X509_bio(certbio, nullptr);

                cert->setX509(x509);

                cert->setCurrencyId(addCertificateScript.currency);
                cert->setExpirationDate(addCertificateScript.expirationDate);
                cert->setRootSignature(addCertificateScript.rootSignature);
                cert->setNonce(txIn->getNonce());

                if (addCertificateScript.isCSCA()) {
                    certStore.addCSCA(cert, blockHeader->getBlockHeight());
                } else if (addCertificateScript.isDSC()) {
                    certStore.addDSC(cert, blockHeader->getBlockHeight());
                }

                BIO_set_close(certbio, BIO_CLOSE);
                BIO_free(certbio);
                delete cert;

                break;
            }
            case SCRIPT_DEACTIVATE_CERTIFICATE: {
                CertStore &certStore = CertStore::Instance();

                DeactivateCertificateScript deactivateCertificateScript;
                CDataStream s(SER_DISK, 1);
                s.write((char *) txIn->getScript().getScript().data(), txIn->getScript().getScript().size());
                s >> deactivateCertificateScript;
                s.clear();
                deactivateCertificateScript.certificateId = txIn->getInAddress();
                deactivateCertificateScript.nonce = txIn->getNonce();

                if(deactivateCertificateScript.isCSCA()) {
                    certStore.deactivateCSCA(deactivateCertificateScript.certificateId, blockHeader);
                } else if(deactivateCertificateScript.isDSC()) {
                    certStore.deactivateDSC(deactivateCertificateScript.certificateId, blockHeader);
                }

                break;
            }
            default: {
                break;
            }
        }
    }

    std::vector<TxOut> txOuts = tx->getTxOuts();
    for (std::vector<TxOut>::iterator txOut = txOuts.begin(); txOut != txOuts.end(); ++txOut) {
        if(wallet.isMine(txOut->getScript())) {
            isMine = true;
        }
        switch(txOut->getScript().getScriptType()) {
            case SCRIPT_PKH: {
                AddressForStore *address = new AddressForStore();

                address->setAmount(txOut->getAmount());
                address->setScript(txOut->getScript());

                if(isRegisterPassportTx) {
                    std::vector<DscToAddressLink> dscToAddressLinks = address->getDscToAddressLinks();

                    DscToAddressLink dscToAddressLink;
                    dscToAddressLink.setDscCertificate(txIns.begin()->getInAddress());
                    dscToAddressLink.setDSCLinkedAtHeight(blockHeader->getBlockHeight());
                    dscToAddressLinks.push_back(dscToAddressLink);

                    address->setDscToAddressLinks(dscToAddressLinks);
                }

                addressStore.creditAddressToStore(address, false);
                break;
            }
            case SCRIPT_VOTE: {
                Vote* vote = new Vote();

                CDataStream dcScript(SER_DISK, 1);
                dcScript.write((char *) tx->getTxOuts().front().getScript().getScript().data(), tx->getTxOuts().front().getScript().getScript().size());
                dcScript >> *vote;
                dcScript.clear();

                vote->setNonce(tx->getTxIns().front().getNonce());
                vote->setFromPubKey(tx->getTxIns().front().getInAddress());

                VoteStore& voteStore = VoteStore::Instance();
                voteStore.applyVote(vote);
                break;
            }
            default: {
                break;
            }
        }
    }

    if(isMine) {
        TransactionForStore transactionForStore;
        transactionForStore.setBlockHash(blockHeader->getHeaderHash());
        transactionForStore.setTx(*tx);

        DB& db = DB::Instance();
        std::chrono::microseconds us = std::chrono::duration_cast< std::chrono::microseconds >(
                std::chrono::system_clock::now().time_since_epoch()
        );
        db.serializeToDb(DB_MY_TRANSACTIONS, Time::getCurrentMicroTimestamp(), transactionForStore);
    }

    return true;
}

bool TransactionHelper::undoTransaction(Transaction* tx, BlockHeader* blockHeader) {
    std::vector<TxIn> txIns = tx->getTxIns();
    AddressStore& addressStore = AddressStore::Instance();
    Wallet& wallet = Wallet::Instance();
    bool isRegisterPassportTx = false;
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        switch(txIn->getScript().getScriptType()) {
            case SCRIPT_PKH: {
                AddressForStore *address = new AddressForStore();
                address->setAmount(txIn->getAmount());

                UScript script;
                script.setScript(txIn->getInAddress());
                script.setScriptType(SCRIPT_LINK);
                address->setScript(script);

                addressStore.creditAddressToStore(address, true);
                break;
            }
            case SCRIPT_REGISTER_PASSPORT: {
                UScript passportScript = txIn->getScript();

                CertStore& certStore = CertStore::Instance();
                DB &db = DB::Instance();

                CDataStream srpscript(SER_DISK, 1);
                srpscript.write((char *) passportScript.getScript().data(), passportScript.getScript().size());

                if((uint32_t)passportScript.getScript().at(0) % 2 == 0) {
                    // is NtpRsk
                    NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();
                    srpscript >> *ntpRskSignatureVerificationObject;

                    db.removeFromDB(DB_NTPSK_ALREADY_USED, ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()));
                } else {
                    // is NtpEsk
                    Cert* cert = certStore.getDscCertWithCertId(txIn->getInAddress());
                    NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = new NtpEskSignatureVerificationObject();
                    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());
                    ntpEskSignatureVerificationObject->setCurveParams(EC_KEY_get0_group(ecKey));
                    srpscript >> *ntpEskSignatureVerificationObject;
                    db.removeFromDB(DB_NTPSK_ALREADY_USED, ntpEskSignatureVerificationObject->getMessageHash());
                }
                srpscript.clear();

                DSCAttachedPassportCounter::decrement(txIn->getInAddress());
                isRegisterPassportTx = true;
                break;
            }

            case SCRIPT_ADD_CERTIFICATE: {
                AddCertificateScript addCertificateScript;
                CDataStream s(SER_DISK, 1);
                s.write((char *) txIn->getScript().getScript().data(), txIn->getScript().getScript().size());
                s >> addCertificateScript;
                s.clear();

                CertStore &certStore = CertStore::Instance();

                Cert *cert = new Cert();

                BIO *certbio = BIO_new_mem_buf(addCertificateScript.certificate.data(), (int)addCertificateScript.certificate.size());
                X509 *x509 = d2i_X509_bio(certbio, NULL);

                cert->setX509(x509);

                if (addCertificateScript.isCSCA()) {
                    certStore.undoLastActionOnCSCA(cert->getId(), CERT_ACTION_ACTIVE);
                } else if (addCertificateScript.isDSC()) {
                    certStore.undoLastActionOnDSC(cert->getId(), CERT_ACTION_ACTIVE);
                }
                break;
            }
            case SCRIPT_DEACTIVATE_CERTIFICATE: {
                DeactivateCertificateScript deactivateCertificateScript;
                CDataStream dcScript(SER_DISK, 1);
                dcScript.write((char *) txIn->getScript().getScript().data(), txIn->getScript().getScript().size());
                dcScript >> deactivateCertificateScript;
                dcScript.clear();

                deactivateCertificateScript.certificateId = txIn->getInAddress();
                deactivateCertificateScript.nonce = txIn->getNonce();

                CertStore &certStore = CertStore::Instance();

                if (deactivateCertificateScript.isCSCA()) {
                    certStore.undoLastActionOnCSCA(deactivateCertificateScript.certificateId, CERT_ACTION_DISABLED);
                } else if (deactivateCertificateScript.isDSC()) {
                    certStore.undoLastActionOnDSC(deactivateCertificateScript.certificateId, CERT_ACTION_DISABLED);
                }

                break;
            }
            case SCRIPT_VOTE: {
                Vote* vote = new Vote();

                CDataStream voScript(SER_DISK, 1);
                voScript.write((char *) tx->getTxOuts().front().getScript().getScript().data(), tx->getTxOuts().front().getScript().getScript().size());
                voScript >> *vote;
                voScript.clear();

                vote->setNonce(tx->getTxIns().front().getNonce());
                vote->setFromPubKey(tx->getTxIns().front().getInAddress());

                VoteStore& voteStore = VoteStore::Instance();
                voteStore.undoVote(vote);
                break;
            }
            default: {
                break;
            }
        }
    }

    std::vector<TxOut> txOuts = tx->getTxOuts();
    for (std::vector<TxOut>::iterator txOut = txOuts.begin(); txOut != txOuts.end(); ++txOut) {
        switch(txOut->getScript().getScriptType()) {
            case SCRIPT_PKH: {
                AddressForStore address = addressStore.getAddressFromStore(AddressHelper::addressLinkFromScript(txOut->getScript()));

                if(isRegisterPassportTx) {

                    std::vector<DscToAddressLink> dscToAddressLinks = address.getDscToAddressLinks();

                    auto it = dscToAddressLinks.begin();
                    while (it != dscToAddressLinks.end()) {
                        if(((DscToAddressLink)*it).getDscCertificate() == txIns.front().getInAddress()) {
                            it = dscToAddressLinks.erase(it);
                            break;
                        }
                    }

                    address.setDscToAddressLinks(dscToAddressLinks);
                }

                addressStore.debitAddressToStore(
                        &address,
                        txOut->getAmount(),
                        true
                );

                break;
            }
            default: {
                break;
            }
        }
    }

    // if(isMine) {}
    // The transaction stays in the MY_TRANSACTIONS store but will be recognized as being invalid / forked out

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
