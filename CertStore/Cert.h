#ifndef PASSPORTREADER_CERT_H
#define PASSPORTREADER_CERT_H

#include <openssl/x509.h>
#include "../Serialization/serialize.h"
#include <boost/serialization/split_member.hpp>
#include <cstdint>
#include <openssl/ossl_typ.h>

class Cert {
private:
    bool calculateId();

    X509* x509;
    std::vector<unsigned char> id;
    uint64_t expirationDate = 0;
    std::vector<unsigned char> rootSignature;
    uint8_t currencyId;
    uint32_t nonce = 0;

    /**
     * status list example
     *  100, true
     *  150, false
     *  300, true
     *
     *  This means, this DSC was active from block 100 to block 150. It then became active again after block 300 until now
     */
    std::vector<std::pair<uint32_t, bool> > statusList;

public:
    std::string getIdAsHexString();
    std::vector<unsigned char> getId();
    EVP_PKEY* getPubKey();
    void prepareForSerialization(const char* certType);
    void finishDeserialization(const char* certType);

    X509 *getX509() const {
        return x509;
    }

    void setX509(X509 *x509) {
        Cert::x509 = x509;
    }

    uint64_t getExpirationDate() {
        return expirationDate;
    }

    void setExpirationDate(uint64_t expirationDate) {
        Cert::expirationDate = expirationDate;
    }

    std::vector<unsigned char> getRootSignature() {
        return rootSignature;
    }

    void setRootSignature(std::vector<unsigned char> rootSignature) {
        Cert::rootSignature = rootSignature;
    }

    uint32_t getNonce();
    void setNonce(uint32_t nonce);
    uint8_t getCurrencyId();
    void setCurrencyId(uint8_t currencyId);
    std::vector<std::pair<uint32_t, bool> > getStatusList();
    void setStatusList(std::vector<std::pair<uint32_t, bool> > statusList);
    void appendStatusList(std::pair<uint32_t, bool> newStatus);
    bool isCertAtive();
    bool isMature(uint32_t blockHeight);

    ~Cert() {
        //X509_free(x509);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(id);
        READWRITE(statusList);
        READWRITE(expirationDate);
        READWRITE(rootSignature);
        READWRITE(currencyId);
        READWRITE(nonce);
    }
};


#endif //PASSPORTREADER_CERT_H
