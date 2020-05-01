
#ifndef TX_DELEGATE_H
#define TX_DELEGATE_H

#include <vector>
#include <sys/types.h>
#include <cstdint>
#include "../Serialization/serialize.h"
#include "Vote.h"

class Delegate {
protected:
    std::vector<unsigned char> publicKey;
    uint32_t voteCount;
    uint32_t unVoteCount;
    std::vector<unsigned char> blockHashLastVote;
    uint32_t nonce;
    std::vector<Vote> votes;
public:

    std::vector<unsigned char> getPublicKey() {
        return publicKey;
    }

    void setPublicKey(std::vector<unsigned char> publicKey) {
        this->publicKey = publicKey;
    }

    uint32_t getVoteCount() {
        return voteCount;
    }

    int32_t getTotalVote() {
        return voteCount - unVoteCount;
    }

    void setVoteCount(uint32_t voteCount) {
        this->voteCount = voteCount;
    }

    uint32_t getUnVoteCount() {
        return unVoteCount;
    }

    void setUnVoteCount(uint32_t unVoteCount) {
        this->unVoteCount = unVoteCount;
    }

    std::vector<unsigned char> getBlockHashLastVote() {
        return blockHashLastVote;
    }

    void setBlockHashLastVote(std::vector<unsigned char> blockHashLastVote) {
        this->blockHashLastVote = blockHashLastVote;
    }

    uint32_t getNonce() {
        return nonce;
    }

    void setNonce(uint32_t nonce) {
        this->nonce = nonce;
    }

    const std::vector<Vote> getVotes() {
        return votes;
    }

    void setVotes(std::vector<Vote> votes) {
        this->votes = votes;
    }

    void appendVote(Vote* vote) {
        this->votes.emplace_back(*vote);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(publicKey);
        READWRITE(voteCount);
        READWRITE(unVoteCount);
        READWRITE(blockHashLastVote);
        READWRITE(nonce);
        READWRITE(votes);
    }
};

#endif //TX_DELEGATE_H
