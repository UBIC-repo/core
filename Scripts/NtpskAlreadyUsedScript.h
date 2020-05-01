
#ifndef UBICD_NTPSKALREADYUSEDSCRIPT_H
#define UBICD_NTPSKALREADYUSEDSCRIPT_H

#include <cstdint>
#include "../Serialization/serialize.h"

struct NtpskAlreadyUsedScript {
    std::vector<unsigned char> address;
    std::vector<unsigned char> dscID;

    const std::vector<unsigned char> &getAddress() const {
        return address;
    }

    void setAddress(const std::vector<unsigned char> &address) {
        NtpskAlreadyUsedScript::address = address;
    }

    const std::vector<unsigned char> &getDscID() const {
        return dscID;
    }

    void setDscID(const std::vector<unsigned char> &dscID) {
        NtpskAlreadyUsedScript::dscID = dscID;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(address);
        READWRITE(dscID);
    }

};

#endif