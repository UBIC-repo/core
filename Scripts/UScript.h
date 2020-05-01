
#ifndef TX_USCRIPT_H
#define TX_USCRIPT_H

#include <cstdint>
#include "../Serialization/serialize.h"

#define KYC_MODE_ANONYMOUS 0
#define KYC_MODE_DG1 1
#define KYC_MODE_DG1_AND_DG2 2

struct UScript {
    // 0x01 link to an existing txoutput
    // 0x02 for PKH
    // 0x03 CSCA/DSC add Certificate
    // 0x04 CSCA/DSC remove Certificate
    // 0x05 Vote
    // 0x06 reserved
    // 0x07 reserved
    // 0x08 reserved
    // 0x09 register passport, only exists as input
    // 0x10 Script Language 1 will be implemented in the future
    // 0x11 Script Language 2 might be implemented in the future
    // 0x12 Script Language 3 might be implemented in the future
    uint8_t scriptType;
    std::vector<unsigned char> script;

    uint8_t getScriptType() const {
        return scriptType;
    }

    void setScriptType(uint8_t scriptType) {
        UScript::scriptType = scriptType;
    }

    const std::vector<unsigned char> &getScript() const {
        return script;
    }

    void setScript(const std::vector<unsigned char> &script) {
        UScript::script = script;
    }

    void setScript(unsigned char* script, uint16_t scriptLength) {
        UScript::script = std::vector<unsigned char>(script, script + scriptLength);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(scriptType);
        READWRITE(script);
    }
};

#endif
