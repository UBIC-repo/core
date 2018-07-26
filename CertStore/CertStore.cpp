#include <fstream>
#include <dirent.h>
#include "CertStore.h"
#include "../Crypto/VerifySignature.h"
#include "../Wallet.h"
#include "../Tools/Hexdump.h"
#include "../FS/FS.h"
#include "../Fixes.h"
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <openssl/x509v3.h>

bool CertStore::addUBICrootCert(Cert* cert, uint32_t blockHeight) {
    this->RootList[cert->getId()] = *cert;
    this->persistToFS("Root", cert->getId());
    return true;
}

bool CertStore::undoLastActionOnRootCert(std::vector<unsigned char> certId, bool actionType) {
    Cert* foundCert = this->getDscCertWithCertId(certId);

    std::vector<std::pair<uint32_t, bool> > statuses = foundCert->getStatusList();

    if(statuses.empty()) {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on Root Cert, empty status list";
        return false;
    }

    if(statuses.back().second == actionType) {
        if (statuses.size() > 1) {
            statuses.pop_back();
            foundCert->setStatusList(statuses);
            this->RootList[certId] = *foundCert;
            this->persistToFS("Root", certId);
        } else {
            std::map<std::vector<unsigned char>, Cert>::iterator it = this->RootList.find(certId);
            this->RootList.erase(it);

            std::vector<unsigned char> path;
            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "root/");
            path = FS::concatPaths(path, certId);

            FS::deleteFile(path);
        }
    } else {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on Root Cert, action mismatch";
        return false;
    }

    return true;
}

bool CertStore::undoLastActionOnCSCA(std::vector<unsigned char> certId, bool actionType) {
    Cert* foundCert = this->getDscCertWithCertId(certId);

    std::vector<std::pair<uint32_t, bool> > statuses = foundCert->getStatusList();
    if(statuses.empty()) {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on CSCA Cert, empty status list";
        return false;
    }

    if(statuses.back().second == actionType) {
        if (statuses.size() > 1) {
            statuses.pop_back();
            foundCert->setStatusList(statuses);
            foundCert->setNonce(foundCert->getNonce() - 1);
            this->CSCAList[certId] = *foundCert;
            this->persistToFS("CSCA", certId);
        } else {
            std::map<std::vector<unsigned char>, Cert>::iterator it = this->CSCAList.find(certId);
            this->CSCAList.erase(it);

            std::vector<unsigned char> path;
            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "csca/");
            path = FS::concatPaths(path, certId);

            FS::deleteFile(path);
        }
    } else {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on CSCA Cert, action mismatch";
        return false;
    }

    return true;
}

bool CertStore::undoLastActionOnDSC(std::vector<unsigned char> certId, bool actionType) {
    Cert* foundCert = this->getDscCertWithCertId(certId);

    std::vector<std::pair<uint32_t, bool> > statuses = foundCert->getStatusList();

    if(statuses.empty()) {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on DSC Cert, empty status list";
        return false;
    }

    if(statuses.back().second == actionType) {
        if (statuses.size() > 1) {
            statuses.pop_back();
            foundCert->setStatusList(statuses);
            foundCert->setNonce(foundCert->getNonce() - 1);
            this->DSCList[Hexdump::vectorToHexString(certId)] = *foundCert;
            this->persistToFS("DSC", certId);
        } else {

            std::unordered_map<std::string, Cert>::iterator it = this->DSCList.find(Hexdump::vectorToHexString(certId));
            this->DSCList.erase(it);

            std::vector<unsigned char> path;
            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "dsc/");
            path = FS::concatPaths(path, certId);

            FS::deleteFile(path);
        }
    } else {
        Log(LOG_LEVEL_INFO) << "cannot undo last action on DSC Cert, action mismatch";
        return false;
    }

    return true;
}

bool CertStore::isSignedByUBICrootCert(std::vector<unsigned char> message, std::vector<unsigned char> signature) {

    for(std::map<std::vector<unsigned char>, Cert>::iterator it = this->RootList.begin(); it != this->RootList.end(); ++it) {
        if (VerifySignature::verify(message, signature, it->second.getPubKey())) {
            return true;
        }
    }

    if(this->RootList.empty()) {
        Log(LOG_LEVEL_INFO) << "Certificate root list is empty";
    }

    return false;
}

bool CertStore::isCertSignedByUBICrootCert(Cert* cert, bool status, uint8_t type) {

    CDataStream s(SER_DISK, 1);
    s << cert->getId();
    s << cert->getExpirationDate();
    s << cert->getCurrencyId();
    s << status; //Active
    s << cert->getNonce();
    s << type;

    Log(LOG_LEVEL_INFO) << "azr 2:" << Hexdump::ucharToHexString((unsigned char*)s.data(), (uint32_t)s.size());

    std::vector<unsigned char> toBeSigned(s.data(), s.data() + s.size());
    s.clear();

    return this->isSignedByUBICrootCert(toBeSigned, cert->getRootSignature());
}

bool CertStore::isCertSignedByCSCA(Cert* cert, uint32_t blockHeight) {
    OpenSSL_add_all_algorithms();
    X509_STORE *store = X509_STORE_new();

    X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM_set_depth(param, 100);
    X509_STORE_set1_param(store, param);
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);

    for(auto it = this->CSCAList.begin(); it != this->CSCAList.end(); ++it) {
        X509_STORE_add_cert(store, it->second.getX509());
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_ANY);
    X509_STORE_CTX_set0_param(ctx, param);
    X509_STORE_CTX_init(ctx, store, cert->getX509(), nullptr);

    int verificationResult = X509_verify_cert(ctx);
    if(verificationResult > 0) {
        X509_OBJECT *cscaObj = X509_OBJECT_new();
        X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, X509_get_issuer_name(cert->getX509()), cscaObj);
        X509* csca = X509_OBJECT_get0_X509(cscaObj);
        Cert* cscaCert = new Cert();
        cscaCert->setX509(csca);
        Cert* recoveredCscaCert = this->getCscaCertWithCertId(cscaCert->getId());

        if(recoveredCscaCert->getId(), recoveredCscaCert->getCurrencyId() != Fixes::fixCertificateCurrencyID(cert->getId(), cert->getCurrencyId())) {
            Log(LOG_LEVEL_ERROR) << "DSC Cert: "
                                 << cert->getId()
                                 << " currrencyID "
                                 << Fixes::fixCertificateCurrencyID(cert->getId(), cert->getCurrencyId())
                                 << " and CSCA cert "
                                 << recoveredCscaCert->getId()
                                 << " currrencyID "
                                 << recoveredCscaCert->getCurrencyId()
                                 << " don't have the same currency ID";
            X509_STORE_CTX_free(ctx);
            return false;
        }

        // There is a ~2 Weeks maturation time for CSCA certificates.
        // This ensures that even if the UBIC Root Cert gets compromised there is a 2 Weeks delay
        // before an attacker could start a serious attack, letting enough time to figure out a solution
        if(recoveredCscaCert->isMature(blockHeight)) {
            Log(LOG_LEVEL_INFO) << "DSC Cert is signed by mature CSCA: " << cert->getId();
            X509_STORE_CTX_free(ctx);
            return true;
        }
        Log(LOG_LEVEL_INFO) << "DSC Cert is signed by CSCA, but " << cert->getId() << " is not yet mature";
        X509_STORE_CTX_free(ctx);
        return false;
    }

    Log(LOG_LEVEL_ERROR) << "DSC Cert " << cert->getId()
                        << " subject:"
                        << X509_NAME_oneline(X509_get_subject_name(cert->getX509()), 0, 0)
                        << " isn't signed by a CSCA";
    Log(LOG_LEVEL_INFO) << "OPEN SSL X509_verify_cert_error_string: " << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
    Log(LOG_LEVEL_INFO) << "error depth: " << X509_STORE_CTX_get_error_depth(ctx);

    X509_STORE_CTX_free(ctx);

    return false;
}

bool CertStore::addCSCA(Cert* cert, uint32_t blockHeight) {
    if(this->isCertSignedByUBICrootCert(cert, true, TYPE_CSCA)) {

        Cert* existingCert = this->getCscaCertWithCertId(cert->getId());

        if(existingCert != nullptr) {
            if(!existingCert->isCertAtive()) {
                existingCert->appendStatusList(std::pair<uint32_t, bool>(blockHeight, true));
                existingCert->setNonce(cert->getNonce() + 1);
                this->CSCAList[cert->getId()] = *existingCert;
                Log(LOG_LEVEL_INFO) << "reactivated CSCA: " << cert->getId();
                return true;
            } else {
                Log(LOG_LEVEL_ERROR) << "cannot reactivate already active CSCA: " << cert->getId();
                return false;
            }
        }
        cert->setCurrencyId(Fixes::fixCertificateCurrencyID(cert->getId(), cert->getCurrencyId()));
        cert->setNonce(cert->getNonce() + 1);
        cert->appendStatusList(std::pair<uint32_t, bool>(blockHeight, true));
        this->CSCAList[cert->getId()] = *cert;
        Log(LOG_LEVEL_INFO) << "added new CSCA: " << cert->getId();

        this->persistToFS("CSCA", cert->getId());
        return true;
    }
    Log(LOG_LEVEL_ERROR) << "failed to add new CSCA, cert is not signed by an UBIC root cert: " << cert->getId();
    return false;
}

bool CertStore::addDSC(Cert* cert, uint32_t blockHeight) {
    if(this->isCertSignedByUBICrootCert(cert, true, TYPE_DSC)) {
        if(this->isCertSignedByCSCA(cert, blockHeight)) {

            Cert* existingCert = this->getDscCertWithCertId(cert->getId());

            if(existingCert != nullptr) {
                if(!existingCert->isCertAtive()) {
                    existingCert->appendStatusList(std::pair<uint32_t, bool>(blockHeight, true));
                    existingCert->setNonce(cert->getNonce() + 1);
                    this->DSCList[Hexdump::vectorToHexString(cert->getId())] = *existingCert;
                    Log(LOG_LEVEL_INFO) << "reactivated DSC: " << cert->getId();
                    return true;
                } else {
                    Log(LOG_LEVEL_ERROR) << "cannot reactivate already active DSC: " << cert->getId();
                    return false;
                }
            }

            cert->appendStatusList(std::pair<uint32_t, bool>(blockHeight, true));
            cert->setNonce(cert->getNonce() + 1);
            cert->setCurrencyId(Fixes::fixCertificateCurrencyID(cert->getId(), cert->getCurrencyId()));

            this->DSCList[Hexdump::vectorToHexString(cert->getId())] = *cert;

            Log(LOG_LEVEL_INFO) << "added new DSC: " << cert->getId();

            this->persistToFS("DSC", cert->getId());
            return true;
        }
        return false;
    }
    Log(LOG_LEVEL_ERROR) << "Cert " << cert->getId() << " is not signed by UBICrootCert";
    return false;
}

bool CertStore::verifyAddCSCA(Cert* cert) {
    if(this->isCertSignedByUBICrootCert(cert, true, TYPE_CSCA)) {
        Cert* existingCert = this->getCscaCertWithCertId(cert->getId());

        if(existingCert != nullptr) {
            if(!existingCert->isCertAtive()) {
                return true;
            } else {
                Log(LOG_LEVEL_ERROR) << "cannot reactivate already active CSCA: " << cert->getId();
                return false;
            }
        }

        return true;
    }
    Log(LOG_LEVEL_ERROR) << "failed to add new CSCA, cert is not signed by an UBIC root cert: " << cert->getId();
    return false;
}

bool CertStore::verifyAddDSC(Cert* cert, uint32_t blockHeight) {
    if(this->isCertSignedByUBICrootCert(cert, true, TYPE_DSC)) {
        if(this->isCertSignedByCSCA(cert, blockHeight)) {

            Cert* existingCert = this->getDscCertWithCertId(cert->getId());

            if(existingCert != nullptr) {
                if(!existingCert->isCertAtive()) {
                    return true;
                } else {
                    Log(LOG_LEVEL_ERROR) << "cannot reactivate already active DSC: " << cert->getId();
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    Log(LOG_LEVEL_ERROR) << "Cert " << cert->getId() << " is not signed by UBICrootCert";
    return false;
}

Cert* CertStore::getDscCertWithCertId(std::vector<unsigned char> certId) {

    Log(LOG_LEVEL_INFO) << "DSCList size: " << (int)this->DSCList.size();

    std::unordered_map<std::string, Cert>::iterator it = this->DSCList.find(Hexdump::vectorToHexString(certId));
    if(it != this->DSCList.end()) {
        return &it->second;
    } else {
        Log(LOG_LEVEL_INFO) << "Cert is not in DSCList: " << certId;
        return nullptr;
    }
}

Cert* CertStore::getCscaCertWithCertId(std::vector<unsigned char> certId) {

    Log(LOG_LEVEL_INFO) << "CSCAList size: " << (int)this->CSCAList.size();

    std::map<std::vector<unsigned char>, Cert>::iterator it = this->CSCAList.find(certId);
    if(it != this->CSCAList.end()) {
        return &it->second;
    } else {
        Log(LOG_LEVEL_INFO) << "Cert is not in CSCAList: " << certId;
        return nullptr;
    }
}

Cert* CertStore::getRootCertWithCertId(std::vector<unsigned char> certId) {


    Log(LOG_LEVEL_INFO) << "RootList size: " << (int)this->RootList.size();

    std::map<std::vector<unsigned char>, Cert>::iterator it = this->RootList.find(certId);
    if(it != this->RootList.end()) {
        return &it->second;
    } else {
        Log(LOG_LEVEL_INFO) << "Cert is not in RootList: " << certId;
        return nullptr;
    }
}

bool CertStore::deactivateRootCert(std::vector<unsigned char> certId, BlockHeader* blockHeader) {

    Cert* existingCert = this->getRootCertWithCertId(certId);

    if(existingCert != nullptr) {
        if(existingCert->isCertAtive()) {
            existingCert->appendStatusList(std::pair<uint64_t, bool>(blockHeader->getBlockHeight(), false));
            this->RootList[existingCert->getId()] = *existingCert;
            Log(LOG_LEVEL_INFO) << "deactivated root cert: " << existingCert->getId();
            this->persistToFS("Root", existingCert->getId());
            return true;
        } else {
            Log(LOG_LEVEL_ERROR) << "cannot deactivate already deactivated root certificate: " << certId;
            return false;
        }
    } else {
        Log(LOG_LEVEL_ERROR) << "cannot find root cert: " << certId;
        return false;
    }
}

/**
 * /!\ WARNING /!\
 * This will not deactivate DSCs signed by this CSCA Cert
 * This has to be done separately
 * @param certId
 * @param blockHeader
 * @return
 */
bool CertStore::deactivateCSCA(std::vector<unsigned char> certId, BlockHeader* blockHeader) {
    Cert* existingCert = this->getCscaCertWithCertId(certId);

    if(existingCert != nullptr) {
        if(existingCert->isCertAtive()) {
            existingCert->appendStatusList(std::pair<uint64_t, bool>(blockHeader->getBlockHeight(), false));
            existingCert->setNonce(existingCert->getNonce() + 1);
            this->CSCAList[existingCert->getId()] = *existingCert;
            Log(LOG_LEVEL_INFO) << "deactivated CSCA cert: " << existingCert->getId();
            this->persistToFS("CSCA", existingCert->getId());
            return true;
        } else {
            Log(LOG_LEVEL_ERROR) << "cannot deactivate already deactivated CSCA: " << certId;
            return false;
        }
    } else {
        Log(LOG_LEVEL_ERROR) << "cannot find CSCA cert: " << certId;
        return false;
    }
}

bool CertStore::deactivateDSC(std::vector<unsigned char> certId, BlockHeader* blockHeader) {

    Cert* existingCert = this->getDscCertWithCertId(certId);

    if(existingCert != nullptr) {
        if(existingCert->isCertAtive()) {
            existingCert->appendStatusList(std::pair<uint64_t, bool>(blockHeader->getBlockHeight(), false));
            existingCert->setNonce(existingCert->getNonce() + 1);
            this->DSCList[Hexdump::vectorToHexString(existingCert->getId())] = *existingCert;
            Log(LOG_LEVEL_INFO) << "deactivated DSC cert: " << existingCert->getId();
            this->persistToFS("DSC", existingCert->getId());
            return true;
        } else {
            Log(LOG_LEVEL_ERROR) << "cannot deactivate already deactivated DSC: " << certId;
            return false;
        }
    } else {
        Log(LOG_LEVEL_ERROR) << "cannot find DSC cert: " << certId;
        return false;
    }
}

void CertStore::loadFromFS() {

    std::vector<unsigned char> path = FS::getCertDirectoryPath();
    path = FS::concatPaths(path, "root/");

    std::vector<std::vector<unsigned char> > fileList = FS::readDir(path);
    for(std::vector<unsigned char> file : fileList) {
        Cert* cert = new Cert();
        FS::deserializeFromFile(file, *cert, CERT_SIZE_MAX);
        cert->finishDeserialization("root");
        this->RootList[cert->getId()] = *cert;
    }
    Log(LOG_LEVEL_INFO) << "Loaded root cert(s)";

    path = FS::getCertDirectoryPath();
    path = FS::concatPaths(path, "csca/");

    fileList = FS::readDir(path);
    for(std::vector<unsigned char> file : fileList) {
        Cert* cert = new Cert();
        FS::deserializeFromFile(file, *cert, CERT_SIZE_MAX);
        cert->finishDeserialization("csca");
        this->CSCAList[cert->getId()] = *cert;
    }
    Log(LOG_LEVEL_INFO) << "Loaded CSCA cert(s)";

    path = FS::getCertDirectoryPath();
    path = FS::concatPaths(path, "dsc/");

    fileList = FS::readDir(path);
    for(std::vector<unsigned char> file : fileList) {
        Cert* cert = new Cert();
        FS::deserializeFromFile(file, *cert, CERT_SIZE_MAX);
        cert->finishDeserialization("dsc");
        this->DSCList[Hexdump::vectorToHexString(cert->getId())] = *cert;
        free(cert);
    }
    Log(LOG_LEVEL_INFO) << "Loaded DSC cert(s)";
}

void CertStore::persistToFS(const char* type, std::vector<unsigned char> certId) {

    std::vector<unsigned char> path;

    if(strcmp("Root", type) == 0) {
        Cert* cert = CertStore::getRootCertWithCertId(certId);

        if(cert != nullptr) {
            std::vector<unsigned char> id = Hexdump::vectorToHexVector(cert->getId());

            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "root/");
            path = FS::concatPaths(path, id);

            cert->prepareForSerialization("root");

            FS::clearFile(path);
            FS::serializeToFile(path, *cert);
        }
    }

    if(strcmp("CSCA", type) == 0) {
        Cert* cert = CertStore::getCscaCertWithCertId(certId);

        if(cert != nullptr) {
            std::vector<unsigned char> id = Hexdump::vectorToHexVector(cert->getId());

            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "csca/");
            path = FS::concatPaths(path, id);

            cert->prepareForSerialization("csca");

            FS::clearFile(path);
            FS::serializeToFile(path, *cert);
        }
    }

    if(strcmp("DSC", type) == 0) {
        Cert* cert = CertStore::getDscCertWithCertId(certId);

        if(cert != nullptr) {
            std::vector<unsigned char> id = Hexdump::vectorToHexVector(cert->getId());

            path = FS::getCertDirectoryPath();
            path = FS::concatPaths(path, "dsc/");
            path = FS::concatPaths(path, id);

            cert->prepareForSerialization("dsc");

            FS::clearFile(path);
            FS::serializeToFile(path, *cert);
        }
    }
}

Cert* CertStore::certFromFile(char* path) {
    Cert* cert = new Cert();

    X509* caCert;
    BIO* certbio = BIO_new(BIO_s_file());
    if(BIO_read_filename(certbio, path) <=0) {
        Log(LOG_LEVEL_ERROR) << "failed to BIO_read_filename " << path;
    }

    if (!(caCert = d2i_X509_bio(certbio, NULL))) {
        Log(LOG_LEVEL_ERROR) << "Error loading cert into memory " << path;
    }
    cert->setX509(caCert);

    BIO_set_close(certbio, BIO_CLOSE);
    BIO_free(certbio);

    return cert;
}

X509 *CertStore::createX509(const unsigned char* c, const unsigned char* cn1, const unsigned char* cn2, X509* signer, EVP_PKEY *pkey) {

    //Wallet::generatePrivateKey(pkey);

    X509 *x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509),1);
    X509_gmtime_adj(X509_get_notBefore(x509),0);
    X509_gmtime_adj(X509_get_notAfter(x509),(long)60*60*24*365*10);

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME *issuerName = NULL;

    X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, cn1, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, cn2, -1, -1, 0);
    X509_set_subject_name(x509, name);

    if(signer == NULL) {
        issuerName = X509_get_subject_name(x509); //self signed
    } else {
        issuerName = X509_get_subject_name(signer);
    }
    X509_set_issuer_name(x509,issuerName);


    if (X509_sign(x509, pkey, EVP_sha256())) {
        Log(LOG_LEVEL_INFO) << "Signed certificate";
    } else {
        Log(LOG_LEVEL_ERROR) << "Failed to sign certificate";
    }

    return x509;
}

std::map<std::vector<unsigned char>, Cert> CertStore::getRootList() {
    return RootList;
}

std::map<std::vector<unsigned char>, Cert>* CertStore::getCSCAList() {
    return &CSCAList;
}

std::unordered_map<std::string, Cert>* CertStore::getDSCList() {
    return &DSCList;
}

