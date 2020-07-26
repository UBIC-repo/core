#include "TransactionApply.h"
#include "../Address.h"
#include "../CertStore/CertStore.h"
#include "../Scripts/DeactivateCertificateScript.h"
#include "../Consensus/VoteStore.h"
#include "../Scripts/AddCertificateScript.h"
#include "../DSCAttachedPassportCounter.h"
#include "../Wallet.h"
#include "../AddressStore.h"
#include "../Scripts/NtpskAlreadyUsedScript.h"
#include "../NtpRsk/NtpRskSignatureVerificationObject.h"
#include "../Tools/Time.h"
#include "../AddressHelper.h"


/**
 * Doesn't verify the Transaction itself, this should already have been done
 *
 * @param tx
 * @param blockHeader
 * @return bool
 */
bool TransactionApply::applyTransaction(Transaction* tx, BlockHeader* blockHeader) {
    std::vector<TxIn> txIns = tx->getTxIns();
    AddressStore& addressStore = AddressStore::Instance();
    Wallet& wallet = Wallet::Instance();
    std::vector<unsigned char> passportHash = std::vector<unsigned char>();
    bool isRegisterPassportTx = false;
    bool isAATransaction = false;
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
                    passportHash = ntpRskSignatureVerificationObject->getMVector();
                    delete ntpRskSignatureVerificationObject;
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
                    passportHash = ntpEskSignatureVerificationObject->getMessageHash();
                    delete ntpEskSignatureVerificationObject;
                }
                srpscript.clear();

                DSCAttachedPassportCounter::increment(txIn->getInAddress());
                isRegisterPassportTx = true;
                break;
            }

            case SCRIPT_AA: {
                isAATransaction = true;
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
                    dscToAddressLink.setPassportHash(passportHash);
                    dscToAddressLinks.push_back(dscToAddressLink);

                    address->setDscToAddressLinks(dscToAddressLinks);
                }

                if(isAATransaction) {
                    address->setAdditionalPassportScans(address->getAdditionalPassportScans() + 1);
                }

                addressStore.creditAddressToStore(address, false);
                delete address;
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

bool TransactionApply::undoTransaction(Transaction* tx, BlockHeader* blockHeader) {
    std::vector<TxIn> txIns = tx->getTxIns();
    AddressStore& addressStore = AddressStore::Instance();
    Wallet& wallet = Wallet::Instance();
    bool isRegisterPassportTx = false;
    bool isAATransaction = false;
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
                    delete ntpRskSignatureVerificationObject;
                } else {
                    // is NtpEsk
                    Cert* cert = certStore.getDscCertWithCertId(txIn->getInAddress());
                    NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = new NtpEskSignatureVerificationObject();
                    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());
                    ntpEskSignatureVerificationObject->setCurveParams(EC_KEY_get0_group(ecKey));
                    srpscript >> *ntpEskSignatureVerificationObject;
                    db.removeFromDB(DB_NTPSK_ALREADY_USED, ntpEskSignatureVerificationObject->getMessageHash());
                    delete ntpEskSignatureVerificationObject;
                }
                srpscript.clear();

                DSCAttachedPassportCounter::decrement(txIn->getInAddress());
                isRegisterPassportTx = true;
                break;
            }

            case SCRIPT_AA: {
                isAATransaction = true;
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

                if(isAATransaction) {
                    address.setAdditionalPassportScans(address.getAdditionalPassportScans() + 1);
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
