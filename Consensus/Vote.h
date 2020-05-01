
#ifndef TX_VOTE_H
#define TX_VOTE_H

#define VOTE_ACTION_VOTE 1
#define VOTE_ACTION_UNVOTE 0

#include <cstdint>
#include <vector>

class Vote {
private:
    uint8_t version = 1;
    uint8_t action;
    std::vector<unsigned char> targetPubKey;
    std::vector<unsigned char> fromPubKey;
    uint32_t nonce;
public:

    uint8_t getVersion() {
        return version;
    }

    void setVersion(uint8_t version) {
        this->version = version;
    }

    uint8_t getAction() {
        return action;
    }

    void setAction(uint8_t action) {
        Vote::action = action;
    }

    const std::vector<unsigned char> getTargetPubKey() {
        return targetPubKey;
    }

    void setTargetPubKey(std::vector<unsigned char> targetPubKey) {
        Vote::targetPubKey = targetPubKey;
    }

    const std::vector<unsigned char> getFromPubKey() {
        return fromPubKey;
    }

    void setFromPubKey(const std::vector<unsigned char> fromPubKey) {
        Vote::fromPubKey = fromPubKey;
    }

    uint32_t getNonce() {
        return nonce;
    }

    void setNonce(uint32_t nonce) {
        Vote::nonce = nonce;
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(action);
        READWRITE(targetPubKey);
        READWRITE(fromPubKey);
        READWRITE(nonce);
    }

};


#endif //TX_VOTE_H
