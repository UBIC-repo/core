
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
    uint8_t version = 2;
    bool isValid;
    std::vector<unsigned char> headerHash;
    std::vector<unsigned char> previousHeaderHash;
    std::vector<unsigned char> merkleRootHash;
    uint32_t blockHeight;
    uint32_t timestamp;
    UAmount payout;
    UAmount payoutRemainder;
    UAmount32 payout32;
    UAmount32 payoutRemainder32;
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
        if(version == 1) {
            READWRITE(payout);
            READWRITE(payoutRemainder);
        } else { // Version 2 or later
            // we do the 32 bit <> 64 bit conversions
            if (std::is_same<Operation, CSerActionSerialize>::value) {
                payout32 = UAmountHelper::UAmount64toUAmount32(payout);
                payoutRemainder32 = UAmountHelper::UAmount64toUAmount32(payoutRemainder);
                READWRITE(payout32);
                READWRITE(payoutRemainder32);
            } else if(std::is_same<Operation, CSerActionUnserialize>::value) {
                READWRITE(payout32);
                READWRITE(payoutRemainder32);
                payout = UAmountHelper::UAmount32toUAmount64(payout32);
                payoutRemainder = UAmountHelper::UAmount32toUAmount64(payoutRemainder32);
            }

        }
        READWRITE(ubiReceiverCount);
        READWRITE(votes);
        READWRITE(issuerPubKey);
        READWRITE(issuerSignature);
    }

};


#endif //TX_BLOCKHEADER_H
