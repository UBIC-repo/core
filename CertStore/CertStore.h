#ifndef PASSPORTREADER_CERTSTORE_H
#define PASSPORTREADER_CERTSTORE_H

#define CERT_ACTION_ACTIVE true
#define CERT_ACTION_DISABLED false

#include <list>
#include <iostream>
#include <openssl/x509.h>
#include <map>
#include <mutex>
#include <cstdint>
#include <unordered_map>
#include "../NtpEsk/NtpEsk.h"
#include "../Countries/Currency.h"
#include "Cert.h"
#include "../BlockHeader.h"

using namespace std;

class CertStore {
private:
    std::map<std::vector<unsigned char>, Cert> RootList;
    std::map<std::vector<unsigned char>, Cert> CSCAList;
    std::unordered_map<std::string, Cert> DSCList;

public:
    static CertStore& Instance(){
        static CertStore instance;
        return instance;
    }
    void loadFromFS();
    void persistToFS(const char* type, std::vector<unsigned char> certId);

    bool isSignedByUBICrootCert(std::vector<unsigned char> message, std::vector<unsigned char> signature);
    bool isCertSignedByUBICrootCert(Cert* cert, bool status, uint8_t type);
    bool isCertSignedByCSCA(Cert* cert, uint32_t blockHeight);
    bool undoLastActionOnRootCert(std::vector<unsigned char> certId, bool actionType);
    bool undoLastActionOnCSCA(std::vector<unsigned char> certId, bool actionType);
    bool undoLastActionOnDSC(std::vector<unsigned char> certId, bool actionType);
    bool addUBICrootCert(Cert* cert, uint32_t blockHeight);
    bool addCSCA(Cert* cert, uint32_t blockHeight);
    bool addDSC(Cert* cert, uint32_t blockHeight);
    bool verifyAddCSCA(Cert* cert);
    bool verifyAddDSC(Cert* cert, uint32_t blockHeight);
    Cert* getDscCertWithCertId(std::vector<unsigned char> certId);
    Cert* getCscaCertWithCertId(std::vector<unsigned char> certId);
    Cert* getRootCertWithCertId(std::vector<unsigned char> certId);
    bool deactivateRootCert(std::vector<unsigned char> certId, BlockHeader* blockHeader);
    bool deactivateCSCA(std::vector<unsigned char> certId, BlockHeader* blockHeader);
    bool deactivateDSC(std::vector<unsigned char> certId, BlockHeader* blockHeader);
    static Cert* certFromFile(char* path);
    static X509 *createX509(const unsigned char* c, const unsigned char* cn1, const unsigned char* cn2, X509* signer,EVP_PKEY *pkey);
    std::map<std::vector<unsigned char>, Cert> getRootList();
    std::map<std::vector<unsigned char>, Cert> getCSCAList();
    std::unordered_map<std::string, Cert> getDSCList();
};

#endif //PASSPORTREADER_CERTSTORE_H
