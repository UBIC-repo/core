#include <vector>
#include "../Serialization/serialize.h"
#include <openssl/evp.h>

#ifndef NTPAA_NTPAAVERIFICATIONOBJECT_H
#define NTPAA_NTPAAVERIFICATIONOBJECT_H

#endif //NTPAA_NTPAAVERIFICATIONOBJECT_H

/***
 * This class provides the verification information to perform an Active Authentication
 * This is useful to
 */
class NtpAAVerificationObject {
private:
    uint8_t version = 1;
    std::vector<unsigned char> blockHash; // block hash that we prove the knowledge of, it has to be issued at least 2 weeks after the initial verification
    uint16_t passportHashAlgorithm;
    std::vector<unsigned char> signedPayload;
    std::vector<unsigned char> signedPayload2; // contains the datagroup hashes
    std::vector<unsigned char> dg15; // contains the public key
    std::vector<unsigned char> aaSignature;
    std::vector<unsigned char> transactionHash;
public:
    uint8_t getVersion() const {
        return version;
    }

    void setVersion(uint8_t version) {
        NtpAAVerificationObject::version = version;
    }

    const std::vector<unsigned char> &getBlockHash() const {
        return blockHash;
    }

    void setBlockHash(const std::vector<unsigned char> &blockHash) {
        NtpAAVerificationObject::blockHash = blockHash;
    }

    uint16_t getPassportHashAlgorithm() const {
        return passportHashAlgorithm;
    }

    void setPassportHashAlgorithm(uint16_t passportHashAlgorithm) {
        NtpAAVerificationObject::passportHashAlgorithm = passportHashAlgorithm;
    }

    const std::vector<unsigned char> &getSignedPayload() const {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        NtpAAVerificationObject::signedPayload = signedPayload;
    }

    const std::vector<unsigned char> &getSignedPayload2() const {
        return signedPayload2;
    }

    void setSignedPayload2(const std::vector<unsigned char> &signedPayload2) {
        NtpAAVerificationObject::signedPayload2 = signedPayload2;
    }

    const std::vector<unsigned char> &getDg15() const {
        return dg15;
    }

    void setDg15(const std::vector<unsigned char> &dg15) {
        NtpAAVerificationObject::dg15 = dg15;
    }

    const std::vector<unsigned char> &getAaSignature() const {
        return aaSignature;
    }

    void setAaSignature(const std::vector<unsigned char> &aaSignature) {
        NtpAAVerificationObject::aaSignature = aaSignature;
    }

    const std::vector<unsigned char> &getTransactionHash() const {
        return transactionHash;
    }

    void setTransactionHash(const std::vector<unsigned char> &transactionHash) {
        NtpAAVerificationObject::transactionHash = transactionHash;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(blockHash);
        READWRITE(passportHashAlgorithm);
        READWRITE(signedPayload);
        READWRITE(signedPayload2); // contains the datagroup hashes
        READWRITE(dg15); // contains the public key
        READWRITE(aaSignature);
    }
};
