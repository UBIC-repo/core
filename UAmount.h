
#ifndef TX_UAMOUNT_H
#define TX_UAMOUNT_H

#include "Serialization/serialize.h"
#include "ChainParams.h"

#include <stdlib.h>
#include <iostream>

typedef uint64_t CAmount;
typedef uint32_t CAmount32;

struct UAmount {
    std::map<uint8_t, CAmount> map;

    uint64_t safeSub(uint64_t n1, uint64_t n2) {
        if(n1 > n2) {
            return n1 - n2;
        }
        
        if(n1 == n2) {
            return 0;
        }

        std::cout << "CRITICAL: safeSub incorrect substraction";
        throw "safeSub incorrect substraction";

        return 0;
    }

    inline UAmount& operator=(UAmount other){
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
        std::map<uint8_t, CAmount> otherMap = other.map;

        if(map.size() != otherMap.size()) {
            return false;
        }

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                return false;
            }
        }

        return true;
    }

    inline bool operator!=(const UAmount& other) {
        std::map<uint8_t, CAmount> otherMap = other.map;

        if(map.size() != otherMap.size()) {
            return true;
        }

        for (std::map<uint8_t, CAmount>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                return true;
            }
        }

        return false;
    }

    inline bool operator==(CAmount other) const {
        return (total() == other);
    }

    inline bool operator!=(CAmount other) const {
        return (total() != other);
    }

    inline bool operator<=(const UAmount& other) {
        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] > it->second) {
                return false;
            }
        }

        return true;
    }

    inline bool operator>=(const UAmount& other) {
        for (std::map<uint8_t, CAmount>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] < it->second) {
                return false;
            }
        }

        return true;
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

    ~UAmount() {
        map.clear();
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

    inline UAmount32& operator=(UAmount32 other){
        map.swap(other.map);
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
        std::map<uint8_t, CAmount32> otherMap = other.map;

        if(map.size() != otherMap.size()) {
            return false;
        }

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                return false;
            }
        }

        return true;
    }

    inline bool operator!=(const UAmount32& other) {
        std::map<uint8_t, CAmount32> otherMap = other.map;

        if(map.size() != otherMap.size()) {
            return true;
        }

        for (std::map<uint8_t, CAmount32>::const_iterator it(map.begin()); it != map.end(); ++it) {
            if(it->second != otherMap[it->first]) {
                return true;
            }
        }

        return false;
    }

    inline bool operator==(CAmount32 other) const {
        return (total() == other);
    }

    inline bool operator!=(CAmount32 other) const {
        return (total() != other);
    }

    inline bool operator<=(const UAmount32& other) {
        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] > it->second) {
                return false;
            }
        }

        return true;
    }

    inline bool operator>=(const UAmount32& other) {
        for (std::map<uint8_t, CAmount32>::const_iterator it(other.map.begin()); it != other.map.end(); ++it) {
            if(map.find(it->first) == map.end() || map[it->first] < it->second) {
                return false;
            }
        }

        return true;
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

    ~UAmount32() {
        map.clear();
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
                 it->first == CURRENCY_LIECHTENSTEIN ||
                 it->first == CURRENCY_ICELAND ||
                 it->first == CURRENCY_HONG_KONG ||
                 it->first == CURRENCY_SPAIN ||
                 it->first == CURRENCY_RUSSIA ||
                 it->first == CURRENCY_ISRAEL ||
                 it->first == CURRENCY_PORTUGAL ||
                 it->first == CURRENCY_DENMARK ||
                 it->first == CURRENCY_TURKEY ||
                 it->first == CURRENCY_ROMANIA ||
                 it->first == CURRENCY_POLAND ||
                 it->first == CURRENCY_NETHERLANDS
                )) {
                return false;
            }
        }

        return true;
    }

    static UAmount UAmount32toUAmount64(UAmount32 amount32) {
        UAmount amount64;
        for (std::map<uint8_t, CAmount32>::const_iterator it(amount32.map.begin()); it != amount32.map.end(); ++it) {
            amount64.map.insert(std::make_pair(it->first, (uint64_t)it->second));
        }

        return amount64;
    }

    static UAmount32 UAmount64toUAmount32(UAmount amount64) {
        UAmount32 amount32;
        for (std::map<uint8_t, CAmount>::const_iterator it(amount64.map.begin()); it != amount64.map.end(); ++it) {
            amount32.map.insert(std::make_pair(it->first, (uint32_t)it->second));
        }

        return amount32;
    }
};

#endif //TX_UAMOUNT_H
