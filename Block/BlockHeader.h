
#ifndef TX_BLOCKHEADER_H
#define TX_BLOCKHEADER_H

#include <cstdint>
#include <string>
#include <map>
#include <list>
#include "../UAmount.h"
#include "../Transaction/Transaction.h"

class BlockHeader {
private:
    uint8_t version = 1;
    bool isValid;
    std::vector<unsigned char> headerHash;
    std::vector<unsigned char> previousHeaderHash;
    std::vector<unsigned char> merkleRootHash;
    uint32_t blockHeight;
    uint32_t timestamp;
    UAmount payout;
    UAmount payoutRemainder;
    UAmount32 ubiReceiverCount;
    std::vector<Transaction> votes;
    std::vector<unsigned char> issuerPubKey;
    std::vector<unsigned char> issuerSignature;
public:
    uint8_t getVersion() const;

    void setVersion(uint8_t version);

    const std::vector<Transaction> &getVotes() const;

    void setVotes(const std::vector<Transaction> &votes);

    std::vector<unsigned char> getHeaderHash();
    void setHeaderHash(std::vector<unsigned char> headerHash);
    std::vector<unsigned char> getPreviousHeaderHash();
    void setPreviousHeaderHash(std::vector<unsigned char> previousHeaderHash);
    const std::vector<unsigned char> getMerkleRootHash();
    void setMerkleRootHash(std::vector<unsigned char> merkleRootHash);
    uint32_t getBlockHeight();
    void setBlockHeight(uint64_t blockHeight);
    uint32_t getTimestamp();
    void setTimestamp(uint64_t timestamp);
    const UAmount getPayout();
    void setPayout(UAmount payout);
    std::vector<unsigned char> getIssuerPubKey();
    void setIssuerPubKey(const std::vector<unsigned char> issuerPubKey);
    std::vector<unsigned char> getIssuerSignature();
    void setIssuerSignature(const std::vector<unsigned char> issuerSignature);
    UAmount32 getUbiReceiverCount();
    void setUbiReceiverCount(UAmount32 ubiReceiverCount);
    UAmount getPayoutRemainder();
    void setPayoutRemainder(UAmount payoutRemainder);
    bool isIsValid();
    void setIsValid(bool isValid);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(headerHash);
        READWRITE(previousHeaderHash);
        READWRITE(merkleRootHash);
        READWRITE(blockHeight);
        READWRITE(timestamp);
        READWRITE(payout);
        READWRITE(payoutRemainder);
        READWRITE(ubiReceiverCount);
        READWRITE(votes);
        READWRITE(issuerPubKey);
        READWRITE(issuerSignature);
    }

};


#endif //TX_BLOCKHEADER_H
