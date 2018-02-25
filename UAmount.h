
#ifndef TX_UAMOUNT_H
#define TX_UAMOUNT_H

#include "serialize.h"
#include "ChainParams.h"

#include <stdlib.h>

typedef uint64_t CAmount;
typedef uint32_t CAmount32;

struct UAmount {
    std::map<uint8_t, CAmount> map;

    uint64_t safeSub(uint64_t n1, uint64_t n2) {
        if(n1 > n2) {
            return n1 - n2;
        }
        return 0;
    }

    inline UAmount& operator=(const UAmount& other){
        map = other.map;
        return *this;
    }

    inline UAmount& operator=(const std::map<uint8_t, CAmount>& other){
        map = other;
        return *this;
    }

    inline void operator+=(const UAmount& other) {
        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            map[it->first] += it->second;
        }
    }

    inline void operator-=(const UAmount& other) {
        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            map[it->first] = safeSub(map[it->first],it->second);
        }
    }

    inline void operator=(const CAmount other) {
        if(other == 0) {
            for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
                map[it->first] = 0;
            }
        }
    }

    inline UAmount operator+(const UAmount& other) {
        UAmount res;
        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            res.map[it->first] += it->second;
        }

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            res.map[it->first] += it->second;
        }
        return res;
    }

    inline UAmount operator-(const UAmount& other) {
        UAmount res;

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            res.map[it->first] = it->second;
        }

        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            res.map[it->first] = safeSub(res.map[it->first], it->second);
        }

        return res;
    }

    inline bool operator==(const UAmount& other) {
        bool equal = true;
        std::map<uint8_t, CAmount> otherMap = other.map;

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                equal = false;
            }
        }
        for (std::map<uint8_t, CAmount>::const_iterator it(otherMap.begin()); it != otherMap.end(); ++it) {
            if(it->second != map[it->first]) {
                equal = false;
            }
        }

        return equal;
    }

    inline bool operator!=(const UAmount& other) {
        bool notEqual = false;
        std::map<uint8_t, CAmount> otherMap = other.map;

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                notEqual = true;
            }
        }
        for (std::map<uint8_t, CAmount>::const_iterator it(otherMap.begin()); it != otherMap.end(); ++it) {
            if(it->second != map[it->first]) {
                notEqual = true;
            }
        }

        return notEqual;
    }

    inline bool operator==(CAmount other) const {
        return (total() == other);
    }

    inline bool operator!=(CAmount other) const {
        return (total() != other);
    }

    inline bool operator<=(const UAmount& other) {
        bool result = true;

        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] > it->second) {
                result = false;
            }
        }

        return result;
    }

    inline bool operator>=(const UAmount& other) {
        bool result = true;

        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] < it->second) {
                result = false;
            }
        }

        return result;
    }

    inline bool operator<(CAmount other) const {
        return (total() < other);
    }

    inline bool operator>(CAmount other) const {
        return (total() > other);
    }

    inline bool operator<=(CAmount other) const {
        return (total() <= other);
    }

    inline bool operator>=(CAmount other) const {
        return (total() >= other);
    }

    CAmount total() const
    {
        CAmount total = 0;
        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            total += it->second;
        }
        return total;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(map);
    }
};


struct UAmount32 {
    std::map<uint8_t, CAmount32> map;

    uint32_t safeSub(uint32_t n1, uint32_t n2) {
        if(n1 > n2) {
            return n1 - n2;
        }
        return 0;
    }

    inline UAmount32& operator=(const UAmount32& other){
        map = other.map;
        return *this;
    }

    inline UAmount32& operator=(const std::map<uint8_t, CAmount32>& other){
        map = other;
        return *this;
    }

    inline void operator+=(const UAmount32& other) {
        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            map[it->first] += it->second;
        }
    }

    inline void operator-=(const UAmount32& other) {
        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            map[it->first] = safeSub(map[it->first],it->second);
        }
    }

    inline void operator=(const CAmount32 other) {
        if(other == 0) {
            for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
                map[it->first] = 0;
            }
        }
    }

    inline UAmount32 operator+(const UAmount32& other) {
        UAmount32 res;
        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            res.map[it->first] += it->second;
        }

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            res.map[it->first] += it->second;
        }
        return res;
    }

    inline UAmount32 operator-(const UAmount32& other) {
        UAmount32 res;

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            res.map[it->first] = it->second;
        }

        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            res.map[it->first] = safeSub(res.map[it->first],it->second);
        }

        return res;
    }

    inline bool operator==(const UAmount32& other) {
        bool equal = true;
        std::map<uint8_t, CAmount32> otherMap = other.map;

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                equal = false;
            }
        }
        for (std::map<uint8_t, CAmount32>::const_iterator it(otherMap.begin()); it != otherMap.end(); ++it) {
            if(it->second != map[it->first]) {
                equal = false;
            }
        }

        return equal;
    }

    inline bool operator!=(const UAmount32& other) {
        bool notEqual = false;
        std::map<uint8_t, CAmount32> otherMap = other.map;

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                notEqual = true;
            }
        }
        for (std::map<uint8_t, CAmount32>::const_iterator it(otherMap.begin()); it != otherMap.end(); ++it) {
            if(it->second != map[it->first]) {
                notEqual = true;
            }
        }

        return notEqual;
    }

    inline bool operator==(CAmount32 other) const {
        return (total() == other);
    }

    inline bool operator!=(CAmount32 other) const {
        return (total() != other);
    }

    inline bool operator<=(const UAmount32& other) {
        bool result = true;

        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] > it->second) {
                result = false;
            }
        }

        return result;
    }

    inline bool operator>=(const UAmount32& other) {
        bool result = true;

        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] < it->second) {
                result = false;
            }
        }

        return result;
    }

    inline bool operator<(CAmount32 other) const {
        return (total() < other);
    }

    inline bool operator>(CAmount32 other) const {
        return (total() > other);
    }

    inline bool operator<=(CAmount32 other) const {
        return (total() <= other);
    }

    inline bool operator>=(CAmount32 other) const {
        return (total() >= other);
    }

    CAmount32 total() const
    {
        CAmount32 total = 0;
        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            total += it->second;
        }
        return total;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(map);
    }
};

class UAmountHelper {
public:
    static bool isValidAmount(UAmount amount) {
        if(amount.map.empty()) {
            return true;
        }

        for (std::map<uint8_t, CAmount>::const_iterator it(amount.map.begin()); it != amount.map.end(); ++it) {
            if(!(it->first == CURRENCY_SWITZERLAND ||
                 it->first == CURRENCY_GERMANY ||
                 it->first == CURRENCY_AUSTRIA ||
                 it->first == CURRENCY_UNITED_KINGDOM ||
                 it->first == CURRENCY_IRELAND ||
                 it->first == CURRENCY_USA ||
                 it->first == CURRENCY_AUSTRALIA ||
                 it->first == CURRENCY_CHINA ||
                 it->first == CURRENCY_SWEDEN ||
                 it->first == CURRENCY_FRANCE ||
                 it->first == CURRENCY_CANADA ||
                 it->first == CURRENCY_JAPAN ||
                 it->first == CURRENCY_THAILAND ||
                 it->first == CURRENCY_NEW_ZEALAND ||
                 it->first == CURRENCY_UNITED_ARAB_EMIRATES ||
                 it->first == CURRENCY_FINLAND ||
                 it->first == CURRENCY_LUXEMBOURG ||
                 it->first == CURRENCY_SINGAPORE ||
                 it->first == CURRENCY_HUNGARY ||
                 it->first == CURRENCY_CZECH_REPUBLIC ||
                 it->first == CURRENCY_MALAYSIA ||
                 it->first == CURRENCY_UKRAINE ||
                 it->first == CURRENCY_ESTONIA ||
                 it->first == CURRENCY_MONACO ||
                 it->first == CURRENCY_LIECHTENSTEIN
                )) {
                return false;
            }
        }

        return true;
    }
};

#endif //TX_UAMOUNT_H
