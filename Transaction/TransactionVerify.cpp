#include "TransactionVerify.h"
#include "TransactionHelper.h"
#include "../CertStore/CertStore.h"
#include "../Serialization/streams.h"
#include "../Tools/Log.h"
#include "../DB/DB.h"
#include "../NtpRsk/NtpRsk.h"
#include "../Chain.h"
#include "../AddressStore.h"
#include "../AddressHelper.h"
#include "../Tools/Time.h"
#include "../Tools/Helper.h"
#include "../CertStore/CertHelper.h"
#include "../Scripts/AddCertificateScript.h"
#include "../Consensus/VoteStore.h"
#include "../Wallet.h"
#include "../Scripts/PkhInScript.h"
#include "../Tools/VectorTool.h"
#include "../Fixes.h"

bool TransactionVerify::verifyRegisterPassportTx(Transaction* tx, uint32_t blockHeight, Cert* cert, TransactionError* transactionError) {

    if(!TransactionHelper::isRegisterPassport(tx)) {
        Log(LOG_LEVEL_ERROR) << "SCRIPT_REGISTER_PASSPORT is not an valid REGISTER_PASSPORT transaction";

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1100);
            transactionError->setErrorMessage("SCRIPT_REGISTER_PASSPORT is not an valid REGISTER_PASSPORT transaction");
        }
        return false;
    }

    TxIn txIn = tx->getTxIns().front();
    UScript script = txIn.getScript();

    if(txIn.getNonce() != 0) {
        Log(LOG_LEVEL_ERROR) << "Nonce must always be 0 for SCRIPT_REGISTER_PASSPORT inputs";

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1101);
            transactionError->setErrorMessage("Nonce must always be 0 for SCRIPT_REGISTER_PASSPORT inputs");
        }
        return false;
    }

    CertStore& certStore = CertStore::Instance();
    if(cert == nullptr) {
        cert = certStore.getDscCertWithCertId(txIn.getInAddress());
        if(cert == nullptr) {
            Log(LOG_LEVEL_ERROR) << "CertStore returned no DSC " << txIn.getInAddress() << " match for the NtpEsk";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1102);
                transactionError->setErrorMessage("CertStore returned no DSC match for the NtpEsk");
                transactionError->setAdditionalDetails1(Hexdump::vectorToHexString(txIn.getInAddress()));
            }
            return false;
        }
    }

    if(cert->getCurrencyId() == 0) {
        Log(LOG_LEVEL_ERROR) << "Cannot register passport because currency id is 0";

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1103);
            transactionError->setErrorMessage("Cannot register passport because currency id is 0");
        }
        return false;
    }

    if(!cert->isCertAtive()) {
        Log(LOG_LEVEL_ERROR) << "Cert is not active " << txIn.getInAddress();

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1104);
            transactionError->setErrorMessage("Cannot register passport because the DSC is not active");
        }
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

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1105);
            transactionError->setErrorMessage("Only ntpsk proofs with version numbers superior to 3 are accepted");
        }
        return false;
    }

    if(blockHeight >= ENFORCE_NTPRSK_VERSION_6_BLOCK_HEIGHT && ntpskVersion == 4) {
        Log(LOG_LEVEL_ERROR) << "After block "
                             << ENFORCE_NTPRSK_VERSION_6_BLOCK_HEIGHT
                             << " only ntprsk proofs with version numbers superior or equal to 6 are accepted";

        if(transactionError != nullptr) {
            transactionError->setErrorCode(1115);
            transactionError->setErrorMessage("Only ntprsk proofs with version numbers superior to 6 are accepted, please upgrade your software");
        }
        return false;
    }

    if(ntpskVersion > 6) {
        Log(LOG_LEVEL_ERROR) << "Unsuported ntpskVersion: " << ntpskVersion;
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
        } catch (const std::exception &exception) {
            Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1106);
                transactionError->setErrorMessage("Failed to deserialize SCRIPT_REGISTER_PASSPORT payload");
            }
            delete ntpRskSignatureVerificationObject;
            return false;
        }

        std::vector<unsigned char> passportHash = ntpRskSignatureVerificationObject->getMVector();

        ntpRskSignatureVerificationObject->setN(n);
        ntpRskSignatureVerificationObject->setE(e);
        ntpRskSignatureVerificationObject->setNmVector(txId);
        ntpRskSignatureVerificationObject->setNm(ECCtools::vectorToBn(txId));

        std::vector<unsigned char> em = ECCtools::bnToVector(ntpRskSignatureVerificationObject->getPaddedM());

        Log(LOG_LEVEL_INFO) << "going to verify padding on: " << em;

        //
        // Begin of padding verification
        //

        // skip this passports for later verification, (those passport's padding doesn't verify anymore after the latest update)
        bool verifiedPadding = Fixes::ignorePaddingForThisPassport(ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()));

        int rsaLen = RSA_size(rsa);

        std::vector<unsigned char> em2;
        em2.emplace_back((unsigned char) 0x00);
        em2.insert(em2.end(), em.begin(), em.end());

        //
        // RSA_padding_check_PKCS1_type_1
        //
        auto recoveredFromPadding = (unsigned char*)malloc(128);
        int recoveredFromPaddingLength = RSA_padding_check_PKCS1_type_1(recoveredFromPadding, (uint32_t) 128, em2.data(),
                                       (uint32_t) em2.size(), rsaLen);

        if(recoveredFromPaddingLength <= 0) {
            recoveredFromPaddingLength = RSA_padding_check_PKCS1_type_2(recoveredFromPadding, (uint32_t) 128, em.data(),
                                                                        (uint32_t) em.size(), rsaLen);
        }
        Log(LOG_LEVEL_INFO) << "OpenSSL error: " << Helper::getOpenSSLError();

        std::vector<unsigned char> recoveredHashVector;
        if (recoveredFromPaddingLength > 0 && !verifiedPadding) {

            //
            // Begin of trying to parse the ASN1 object if it is one
            //
            if(recoveredFromPaddingLength > 32) {
                Log(LOG_LEVEL_INFO) << "recoveredFromPadding: "
                                    << Hexdump::ucharToHexString(recoveredFromPadding, recoveredFromPaddingLength);
                STACK_OF(ASN1_TYPE) *asn1Sequence = NULL;
                asn1Sequence = d2i_ASN1_SEQUENCE_ANY(NULL, const_cast<const unsigned char**>(&recoveredFromPadding), recoveredFromPaddingLength);
                if (asn1Sequence != NULL) {
                    if (sk_ASN1_TYPE_num(asn1Sequence) >= 2) {
                        ASN1_TYPE* asn1Hash = sk_ASN1_TYPE_value(asn1Sequence, 1);
                        unsigned char asn1PassportHash[64];
                        int asn1PassportHashLength = ASN1_TYPE_get_octetstring(asn1Hash, asn1PassportHash, 64);
                        recoveredHashVector = std::vector<unsigned char>(asn1PassportHash, asn1PassportHash + asn1PassportHashLength);
                    }
                }
            } else {
                recoveredHashVector = std::vector<unsigned char>(recoveredFromPadding, recoveredFromPadding + recoveredFromPaddingLength);
            }
            //
            // End of trying to parse the ASN1 object if it is one
            //

            if(passportHash != recoveredHashVector) {
                Log(LOG_LEVEL_INFO) << "passport hash: "
                                    << passportHash;
                Log(LOG_LEVEL_INFO) << "recovered hash: "
                                    << recoveredHashVector;
                Log(LOG_LEVEL_INFO) << "Payload: "
                                    << Hexdump::vectorToHexString(ntpRskSignatureVerificationObject->getSignedPayload());
                Log(LOG_LEVEL_INFO) << "Recovered hash mismatch";

                if (transactionError != nullptr) {
                    transactionError->setErrorCode(1197);
                    transactionError->setErrorMessage("Recovered hash mismatch");
                }
                return false;
            }
            Log(LOG_LEVEL_INFO) << "Register passport: Padding verified";
            verifiedPadding = true;
        }

        Log(LOG_LEVEL_INFO) << "passport hash: " << ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM());
        Log(LOG_LEVEL_INFO) << "recovered hash: " << recoveredHashVector;
        Log(LOG_LEVEL_INFO) << "Payload: " << Hexdump::vectorToHexString(ntpRskSignatureVerificationObject->getSignedPayload());

        //
        // RSA_verify_PKCS1_PSS
        //
        if (!verifiedPadding) {
            //@TODO if the hash starts with 00 this will fail
            em = VectorTool::prependToCorrectSize(em);

            if (RSA_verify_PKCS1_PSS(rsa, passportHash.data(), EVP_sha256(), em.data(), -2) == 1) { // -2 = RSA_PSS_SALTLEN_AUTO
                Log(LOG_LEVEL_INFO) << "Register passport: PKCS1_PSS verified with SHA256";
                verifiedPadding = true;
            }
            Log(LOG_LEVEL_INFO) << "OpenSSL error: " << Helper::getOpenSSLError();
        }

        //@TODO SHA512 and SHA1 padding

        if (!verifiedPadding) {
            Log(LOG_LEVEL_ERROR) << "Failed to verify padding";
            Log(LOG_LEVEL_INFO) << "em : " << em;
            Log(LOG_LEVEL_INFO) << "em2 : " << em2;

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1107);
                transactionError->setErrorMessage("Failed to verify RSA padding");
            }
            delete ntpRskSignatureVerificationObject;
            return false;
        }

        //
        // end of padding verification
        //

        // verify proof not already used
        DB& db = DB::Instance();
        if(db.isInDB(DB_NTPSK_ALREADY_USED, ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()))) {
            Log(LOG_LEVEL_ERROR) << "NtpRsk " << ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM()) << " already used";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1109);
                transactionError->setErrorMessage("Passport is already registered");
                transactionError->setAdditionalDetails1(Hexdump::vectorToHexString(ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM())));
            }
            delete ntpRskSignatureVerificationObject;
            return false;
        }

        // Verify NtpEsk proof itself
        if(!NtpRsk::verifyNtpRsk(ntpRskSignatureVerificationObject)) {
            Log(LOG_LEVEL_ERROR) << "NtpRsk failed";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1110);
                transactionError->setErrorMessage("NtpRsk failed verification failed");
            }
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

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1111);
                transactionError->setErrorMessage("Failed to deserialize SCRIPT_REGISTER_PASSPORT payload");
            }
            return false;
        }

        // verify proof not already used
        DB &db = DB::Instance();
        if (db.isInDB(DB_NTPSK_ALREADY_USED, ntpEskSignatureVerificationObject->getMessageHash())) {
            Log(LOG_LEVEL_ERROR) << "NtpEsk " << ntpEskSignatureVerificationObject->getMessageHash()
                                 << " already used";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1113);
                transactionError->setErrorMessage("Passport is already registered");
                transactionError->setAdditionalDetails1(Hexdump::vectorToHexString(ntpEskSignatureVerificationObject->getMessageHash()));
            }
            delete ntpEskSignatureVerificationObject;
            return false;
        }

        // Verify NtpEsk proof itself
        if(!NtpEsk::verifyNtpEsk(ntpEskSignatureVerificationObject)) {
            Log(LOG_LEVEL_ERROR) << "NtpEsk failed";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1114);
                transactionError->setErrorMessage("NtpEsk failed");
            }
            delete ntpEskSignatureVerificationObject;
            return false;
        }

        delete ntpEskSignatureVerificationObject;
    }

    if (blockHeight > MAXIMUM_PASSPORTS_PER_ADDRESS_ACTIVATION_HEIGHT) {
        TxOut txOut = tx->getTxOuts().front();
        UScript outScript = txOut.getScript();
        AddressStore &addressStore = AddressStore::Instance();
        std::vector<unsigned char> addressKey = AddressHelper::addressLinkFromScript(outScript);
        AddressForStore outAddress = addressStore.getAddressFromStore(addressKey);

        if (!outAddress.getDscToAddressLinks().empty() &&
            outAddress.getDscToAddressLinks().size() > MAXIMUM_PASSPORTS_PER_ADDRESS) {
            if(transactionError != nullptr) {
                transactionError->setErrorCode(1115);
                transactionError->setErrorMessage("Maximum number of passport reached for this address");
                transactionError->setAdditionalDetails1(std::to_string(MAXIMUM_PASSPORTS_PER_ADDRESS));
            }
            return false;
        }
    }

    return true;
}

bool TransactionVerify::verifyNetworkTx(TransactionForNetwork* txForNetwork, TransactionError* transactionError) {

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

    if(verifyTx(&tx, IGNORE_IS_IN_HEADER, bestHeader, transactionError)) {
        return true;
    }

    if(TransactionHelper::isRegisterPassport(&tx) && txForNetwork->getAdditionalPayloadType() == PAYLOAD_TYPE_DSC_CERTIFICATE) {
        // the passport transaction is a special case
        // It requires to take into account the additionalPayload field

        std::vector<unsigned char> payload = txForNetwork->getAdditionalPayload();
        BIO *certbio = BIO_new_mem_buf((void*)payload.data(),
                                       (int)payload.size());

        X509 *x509 = d2i_X509_bio(certbio, nullptr);

        if(x509 == nullptr) {
            BIO_free(certbio);

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1001);
                transactionError->setErrorMessage("Could not deserialize x509 certificate");
            }
            return false;
        }

        uint8_t currencyId = CertHelper::getCurrencyIdForCert(x509);
        if(currencyId == 0) {
            X509_free(x509);
            BIO_free(certbio);

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1002);
                transactionError->setErrorMessage("No currency found for the x509 certificate");
            }
            return false;
        }

        uint64_t expiration = CertHelper::calculateDSCExpirationDateForCert(x509);
        if(expiration < Time::getCurrentTimestamp() + 600) { //expired or going to expire very soon
            X509_free(x509);
            BIO_free(certbio);

            if(transactionError != nullptr) {
                transactionError->setErrorCode(1003);
                transactionError->setErrorMessage("The passport is expired, or will expire soon");
            }
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
            // No TransactionError return here, the error was already set previously
            return false;
        }

        if(!certStore.isCertSignedByCSCA(&cert, chain.getCurrentBlockchainHeight())) {
            X509_free(x509);
            BIO_free(certbio);
            if(transactionError != nullptr) {
                transactionError->setErrorCode(1004);
                transactionError->setErrorMessage("The Document Signing Certificate is not signed by any CSCA");
            }
            return false;
        }

        // if it's an RSA certificate verify that the exponent >= 65537
        EVP_PKEY* pkey = X509_get0_pubkey(x509);
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);

        if(rsa != nullptr) {
            const BIGNUM* exponent = BN_new();
            BIGNUM* minExponent = BN_new();
            RSA_get0_key(rsa, nullptr, &exponent, nullptr);
            BN_dec2bn(&minExponent, "65537");

            if (BN_cmp(exponent, minExponent) == -1) {
                Log(LOG_LEVEL_ERROR) << "SCRIPT_ADD_CERTIFICATE failed because RSA exponent is too small minimum required is 65537";
                if(transactionError != nullptr) {
                    transactionError->setErrorCode(1005);
                    transactionError->setErrorMessage("The Document Signing Certificate exponent is too small");
                }
                return false;
            }
        }

        bool verified = verifyRegisterPassportTx(&tx, chain.getCurrentBlockchainHeight(), &cert, transactionError);

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
bool TransactionVerify::verifyTx(Transaction* tx, uint8_t isInHeader, BlockHeader* header, TransactionError* transactionError) {

    Chain& chain = Chain::Instance();
    BlockHeader* bestHeader = chain.getBestBlockHeader();

    if(TransactionHelper::getTxSize(tx) > TRANSACTION_SIZE_MAX) {
        Log(LOG_LEVEL_ERROR) << "transaction is of size"
                             << TransactionHelper::getTxSize(tx)
                             << " but maximum allowed transaction size is "
                             << TRANSACTION_SIZE_MAX;

        if(transactionError != nullptr) {
            transactionError->setErrorCode(901);
            transactionError->setErrorMessage("The transaction is bigger than the maximum allowed transaction size");
            transactionError->setAdditionalDetails1(std::to_string(TransactionHelper::getTxSize(tx)));
            transactionError->setAdditionalDetails2(std::to_string(TRANSACTION_SIZE_MAX));
        }
        return false;
    }

    AddressStore& addressStore = AddressStore::Instance();

    uint32_t txInputCount = tx->getTxIns().size();
    uint32_t txOutputCount = tx->getTxOuts().size();

    if(tx->getNetwork() != NET_CURRENT) {
        Log(LOG_LEVEL_ERROR) << "transaction with wrong network id " << tx->getNetwork();

        if(transactionError != nullptr) {
            transactionError->setErrorCode(902);
            transactionError->setErrorMessage("The transaction is using the wrong network ID");
        }
        return false;
    }

    UAmount totalInAmount;
    UAmount totalOutAmount;
    UAmount addressAvailableAmount;
    std::vector<TxIn> txIns = tx->getTxIns();
    std::map<std::vector<unsigned char>, bool> txInsDuplicates = std::map<std::vector<unsigned char>, bool> ();
    for (std::vector<TxIn>::iterator txIn = txIns.begin(); txIn != txIns.end(); ++txIn) {
        if(txInsDuplicates.find(txIn->getInAddress()) != txInsDuplicates.end()) {
            Log(LOG_LEVEL_ERROR) << "Same input is duplicated";
            return false;
        }
        txInsDuplicates.insert(std::make_pair(txIn->getInAddress(), true));
        UAmount inAmount = txIn->getAmount();
        if(!UAmountHelper::isValidAmount(inAmount)) {
            Log(LOG_LEVEL_ERROR) << "Invalid inAmount: "
                                 << inAmount;

            if(transactionError != nullptr) {
                transactionError->setErrorCode(903);
                transactionError->setErrorMessage("Invalid inAmount");
            }
            return false;
        }

        UAmount newTotalInAmount = totalInAmount + inAmount;
        if(totalInAmount >= newTotalInAmount && totalInAmount != newTotalInAmount) {
            Log(LOG_LEVEL_ERROR) << "Invalid inAmount: "
                                 << inAmount;
            return false;
        }
        totalInAmount = newTotalInAmount;
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

        if(transactionError != nullptr) {
            transactionError->setErrorCode(904);
            transactionError->setErrorMessage("The transaction is trying to spend more than it's balance");
        }
        return false;
    }

    std::vector<TxOut> txOuts = tx->getTxOuts();
    for (std::vector<TxOut>::iterator txOut = txOuts.begin(); txOut != txOuts.end(); ++txOut) {
        UAmount outAmount = txOut->getAmount();
        if(!UAmountHelper::isValidAmount(outAmount)) {
            Log(LOG_LEVEL_ERROR) << "invalid outAmount: "
                                 << outAmount;

            if(transactionError != nullptr) {
                transactionError->setErrorCode(905);
                transactionError->setErrorMessage("Invalid outAmount");
            }
            return false;
        }

        UAmount newTotalOutAmount = totalOutAmount + outAmount;
        if(totalOutAmount >= newTotalOutAmount && totalInAmount != newTotalOutAmount) {
            Log(LOG_LEVEL_ERROR) << "Invalid outAmount: "
                                 << outAmount;
            return false;
        }
        totalOutAmount = newTotalOutAmount;

        switch(txOut->getScript().getScriptType()) {
            case SCRIPT_LINK: {
                //@TODO verify LINK exists
                Log(LOG_LEVEL_ERROR) << "SCRIPT_LINK deactivated for now";
                if(transactionError != nullptr) {
                    transactionError->setErrorCode(999);
                    transactionError->setErrorMessage("SCRIPT_LINK deactivated for now");
                }
                return false;
            }
            case SCRIPT_VOTE: {
                break;
            }
            case SCRIPT_PKH: {
                if(header->getBlockHeight() > ENFORCE_PKH_LENGTH_BLOCK_HEIGHT) {
                    if(txOut->getScript().getScript().size() != 20) {
                        Log(LOG_LEVEL_ERROR) << "Invalid PKH script size, expected 20, got " << (uint32_t)txOut->getScript().getScript().size();
                        return false;
                    }
                }
                break;
            }
            default: {
                Log(LOG_LEVEL_CRITICAL_ERROR) << "Unknown TxOut script type: " << txOut->getScript().getScriptType();

                if(transactionError != nullptr) {
                    transactionError->setErrorCode(998);
                    transactionError->setErrorMessage("Unknown TxOut script type");
                }
                return false;
            }
        }
    }

    if(!(totalInAmount >= totalOutAmount)) {
        Log(LOG_LEVEL_ERROR) << "outAmount > inAmount " << " inAmount : " << totalInAmount << " outAmount : " << totalOutAmount;

        if(transactionError != nullptr) {
            transactionError->setErrorCode(906);
            transactionError->setErrorMessage("OutAmount is higher than the inAmount");
        }
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(906);
                        transactionError->setErrorMessage("Wrong nonce");
                        transactionError->setAdditionalDetails1(std::to_string(txIn->getNonce()));
                        transactionError->setAdditionalDetails2(std::to_string(TransactionHelper::getNonce(txIn->getInAddress())));
                        transactionError->setAdditionalDetails3(Hexdump::vectorToHexString(txIn->getInAddress()));
                    }
                    return false;
                }

                Log(LOG_LEVEL_ERROR) << "SCRIPT_LINK deactivated for now";

                if(transactionError != nullptr) {
                    transactionError->setErrorCode(999);
                    transactionError->setErrorMessage("SCRIPT_LINK deactivated for now");
                }
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(906);
                        transactionError->setErrorMessage("Wrong nonce");
                        transactionError->setAdditionalDetails1(std::to_string(txIn->getNonce()));
                        transactionError->setAdditionalDetails2(std::to_string(TransactionHelper::getNonce(txIn->getInAddress())));
                        transactionError->setAdditionalDetails3(Hexdump::vectorToHexString(txIn->getInAddress()));
                    }
                    return false;
                }
                PkhInScript pkhInScript;

                try {
                    CDataStream pkhscript(SER_DISK, 1);
                    pkhscript.write((char *) script.getScript().data(), script.getScript().size());
                    pkhscript >> pkhInScript;
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_PKH payload";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(907);
                        transactionError->setErrorMessage("Failed to deserialize SCRIPT_PKH payload");
                    }
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

                            if(transactionError != nullptr) {
                                transactionError->setErrorCode(908);
                                transactionError->setErrorMessage("Recovered address doesn't equal inAddress");
                            }
                            return false;
                        }

                        if(!VerifySignature::verify(txId, pkhInScript.signature, pkhInScript.publicKey)) {
                            Log(LOG_LEVEL_ERROR) << "Signature verification failed for transaction: " << txId
                                                 << " Signature: "
                                                 << pkhInScript.signature
                                                 << " Public key: "
                                                 << pkhInScript.publicKey;

                            if(transactionError != nullptr) {
                                transactionError->setErrorCode(909);
                                transactionError->setErrorMessage("Signature verification failed");
                            }
                            return false;
                        }
                        break;
                    }
                    default: {
                        Log(LOG_LEVEL_ERROR) << "Unknown pkhInScript version " << pkhInScript.getVersion();

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(910);
                            transactionError->setErrorMessage("Unknown pkhInScript version");
                        }
                        return false;
                    }
                }

                break;
            }
            case SCRIPT_REGISTER_PASSPORT: {
                if(!TransactionVerify::verifyRegisterPassportTx(tx, header->getBlockHeight(), nullptr, transactionError)) {
                    Log(LOG_LEVEL_INFO) << "Failed to verify register passport transaction";
                    // no TransactionError here, it is already set in the verifyRegisterPassportTx function
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(911);
                        transactionError->setErrorMessage("Failed to deserialize SCRIPT_ADD_CERTIFICATE payload");
                    }
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

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(912);
                            transactionError->setErrorMessage("SCRIPT_ADD_CERTIFICATE failed because RSA exponent is too small minimum required is 65537");
                        }
                        return false;
                    }
                }

                uint32_t currentHeaderTimeStamp = 0;
                if(header != nullptr) {
                    currentHeaderTimeStamp = header->getTimestamp();
                }

                if(addCertificateScript.expirationDate < currentHeaderTimeStamp) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_ADD_CERTIFICATE failed because it is expired, addCertificateScript.expirationDate:"
                                         << addCertificateScript.expirationDate;

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(912);
                        transactionError->setErrorMessage("SCRIPT_ADD_CERTIFICATE failed because it is expired, addCertificateScript.expirationDate");
                        transactionError->setAdditionalDetails1(std::to_string(addCertificateScript.expirationDate));
                    }
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(913);
                        transactionError->setErrorMessage("txIn->getInAddress() and cert->getId() mismatch");
                        transactionError->setAdditionalDetails1(Hexdump::vectorToHexString(txIn->getInAddress()));
                        transactionError->setAdditionalDetails1(Hexdump::vectorToHexString(cert->getId()));
                    }
                    return false;
                }

                CertStore& certStore = CertStore::Instance();

                if(addCertificateScript.isCSCA()) {
                    if(!certStore.verifyAddCSCA(cert)) {
                        Log(LOG_LEVEL_ERROR) << "verifyAddCSCA failed";

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(914);
                            transactionError->setErrorMessage("verifyAddCSCA failed");
                        }
                        return false;
                    }
                } else if(addCertificateScript.isDSC()) {
                    if(!certStore.verifyAddDSC(cert, header->getBlockHeight())) {
                        Log(LOG_LEVEL_ERROR) << "verifyAddDSC failed";

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(915);
                            transactionError->setErrorMessage("verifyAddDSC failed");
                        }
                        return false;
                    }
                }

                if(addCertificateScript.type == TYPE_CSCA && !certStore.isCertSignedByUBICrootCert(cert, true, addCertificateScript.type)) {
                    Log(LOG_LEVEL_ERROR) << "cert: " << cert->getId() << " is not signed by UBIC root Cert";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(916);
                        transactionError->setErrorMessage("Certificate is not signed is not signed by UBIC root Cert");
                    }
                    return false;
                }

                if(addCertificateScript.isCSCA()) {
                    cert = certStore.getCscaCertWithCertId(txIn->getInAddress());
                } else if(addCertificateScript.isDSC()) {
                    if(!certStore.isCertSignedByCSCA(cert, chain.getCurrentBlockchainHeight())) {
                        Log(LOG_LEVEL_ERROR) << "DSC: " << cert->getId() << " is not signed by a CSCA";

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(917);
                            transactionError->setErrorMessage("DSC is not signed by a CSCA");
                        }
                        return false;
                    }
                    cert = certStore.getDscCertWithCertId(txIn->getInAddress());
                } else {
                    Log(LOG_LEVEL_ERROR) << "unknown addCertificateScript type: " << addCertificateScript.type;

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(918);
                        transactionError->setErrorMessage("Unknown addCertificateScript type");
                        transactionError->setAdditionalDetails1(std::to_string(addCertificateScript.type));
                    }
                    return false;
                }

                if(cert != nullptr) {
                    if(cert->getNonce() != txIn->getNonce()) {
                        Log(LOG_LEVEL_ERROR) << "add certificate, wrong nonce for certificate: " << cert->getId();

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(919);
                            transactionError->setErrorMessage("Add certificate, wrong nonce");
                        }
                        return false;
                    }

                    if(cert->isCertAtive()) {
                        Log(LOG_LEVEL_ERROR) << "cannot activate already active certificate: " << cert->getId();

                        if(transactionError != nullptr) {
                            transactionError->setErrorCode(920);
                            transactionError->setErrorMessage("Cannot activate already active certificate");
                        }
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(921);
                        transactionError->setErrorMessage("Failed to deserialize SCRIPT_DEACTIVATE_CERTIFICATE payload");
                    }
                    return false;
                }

                CertStore& certStore = CertStore::Instance();
                Cert* cert = new Cert();

                if(!deactivateCertificateScript.isDSC() && !deactivateCertificateScript.isCSCA()) {
                    Log(LOG_LEVEL_ERROR) << "Unknown certificate type: " << deactivateCertificateScript.type;

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(922);
                        transactionError->setErrorMessage("Unknown certificate type");
                        transactionError->setAdditionalDetails1(std::to_string(deactivateCertificateScript.type));
                    }
                    return false;
                }

                if(deactivateCertificateScript.isDSC()) {
                    cert = certStore.getDscCertWithCertId(deactivateCertificateScript.certificateId);
                } else if(deactivateCertificateScript.isCSCA()) {
                    cert = certStore.getCscaCertWithCertId(deactivateCertificateScript.certificateId);
                }

                if(deactivateCertificateScript.nonce != cert->getNonce()) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_DEACTIVATE_CERTIFICATE nonce mismatch";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(923);
                        transactionError->setErrorMessage("SCRIPT_DEACTIVATE_CERTIFICATE nonce mismatch");
                    }
                    return false;
                }

                if(!certStore.isSignedByUBICrootCert(
                        TransactionHelper::getDeactivateCertificateScriptId(deactivateCertificateScript),
                        deactivateCertificateScript.rootCertSignature)
                        ) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_DEACTIVATE_CERTIFICATE not signed by Root Cert";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(924);
                        transactionError->setErrorMessage("SCRIPT_DEACTIVATE_CERTIFICATE not signed by Root Cert");
                    }
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

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(925);
                        transactionError->setErrorMessage("SCRIPT_VOTE signature verification failed");
                    }
                    return false;
                }

                if(txInputCount != 1 || txOutputCount != 1) {
                    Log(LOG_LEVEL_ERROR) << "SCRIPT_VOTE transactions are only allowed to have one input and one output";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(926);
                        transactionError->setErrorMessage("SCRIPT_VOTE transactions are only allowed to have one input and one output");
                    }
                    return false;
                }

                Vote* vote = new Vote();

                try {
                    CDataStream dcScript(SER_DISK, 1);
                    dcScript.write((char *) tx->getTxOuts().front().getScript().getScript().data(), tx->getTxOuts().front().getScript().getScript().size());
                    dcScript >> *vote;
                } catch (const std::exception& e) {
                    Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_VOTE payload";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(927);
                        transactionError->setErrorMessage("Failed to deserialize SCRIPT_VOTE payload");
                    }
                    return false;
                }

                vote->setNonce(txIn->getNonce());
                vote->setFromPubKey(txIn->getInAddress());

                VoteStore& voteStore = VoteStore::Instance();
                if(!voteStore.verifyVote(vote)) {
                    Log(LOG_LEVEL_ERROR) << "voteStore.verifyVote failed";

                    if(transactionError != nullptr) {
                        transactionError->setErrorCode(928);
                        transactionError->setErrorMessage("voteStore.verifyVote failed");
                    }
                    return false;
                }

                isVote = true;
                needToPayFee = false;

                break;
            }
            default: {
                Log(LOG_LEVEL_CRITICAL_ERROR) << "unknown script type " << script.getScriptType();

                if(transactionError != nullptr) {
                    transactionError->setErrorCode(929);
                    transactionError->setErrorMessage("Unknown script type");
                    transactionError->setAdditionalDetails1(std::to_string(script.getScriptType()));
                }
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

            if(transactionError != nullptr) {
                transactionError->setErrorCode(930);
                transactionError->setErrorMessage("Transaction doesn't pay the minimum txFee");
            }
            return false;
        }
    }

    // make sure votes are in the header and other transactions aren't
    if(isInHeader != IGNORE_IS_IN_HEADER) {
        if(isVote && isInHeader == IS_NOT_IN_HEADER) {
            Log(LOG_LEVEL_ERROR) << "Transaction is a vote but it isn't in the block header as expected";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(931);
                transactionError->setErrorMessage("Transaction is a vote but it isn't in the block header as expected");
            }
            return false;
        } else if(!isVote && isInHeader == IS_IN_HEADER) {
            Log(LOG_LEVEL_ERROR) << "Transaction is not a vote but it is in the block header";

            if(transactionError != nullptr) {
                transactionError->setErrorCode(932);
                transactionError->setErrorMessage("Transaction is not a vote but it is in the block header");
            }
            return false;
        }
    }

    return true;
}
