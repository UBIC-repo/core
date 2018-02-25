
#ifndef TX_DSCATTACHEDPASSPORTCOUNTER_H
#define TX_DSCATTACHEDPASSPORTCOUNTER_H

#include <cstdint>
#include <vector>
#include "serialize.h"

class DSCAttachedPassportCounter {
public:
    static bool increment(std::vector<unsigned char> dscId);
    static bool decrement(std::vector<unsigned char> dscId);
    static uint64_t getCount(std::vector<unsigned char> dscId);
};

struct DSCAttachedPassportCount{
    uint32_t count;

    inline DSCAttachedPassportCount& operator=(const DSCAttachedPassportCount& other){
        count = other.count;
        return *this;
    }

    inline DSCAttachedPassportCount& operator=(const uint32_t other){
        count = other;
        return *this;
    }

    DSCAttachedPassportCount operator++(int) {
        count++;
        return *this;
    }

    DSCAttachedPassportCount operator--(int) {
        count--;
        return *this;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(count);
    }

};


#endif //TX_DSCATTACHEDPASSPORTCOUNTER_H
