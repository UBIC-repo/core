
#ifndef TX_NETWORKCOMMANDS_H
#define TX_NETWORKCOMMANDS_H

#define ASK_FOR_BLOCKS_COMMAND 0x01
#define ASK_FOR_BLOCK_COMMAND 0x02
#define ASK_FOR_PEERS_COMMAND 0x03
#define ASK_FOR_BEST_BLOCK_HEADER_COMMAND 0x04
#define ASK_FOR_BLOCKCHAIN_HEIGHT_COMMAND 0x05
#define ASK_FOR_VERSION_COMMAND 0x06
#define ASK_FOR_STATUS_COMMAND 0x07
#define ASK_FOR_DONATION_ADDRESS_COMMAND 0x08
#define ASK_FOR_BLOCKS_USING_DATA_PACKET_SIZE 0x09
#define TRANSMIT_TRANSACTIONS_COMMAND 0x11
#define TRANSMIT_BLOCK_COMMAND 0x12
#define TRANSMIT_PEERS_COMMAND 0x13
#define TRANSMIT_BEST_BLOCK_HEADER_COMMAND 0x14
#define TRANSMIT_BLOCKCHAIN_HEIGHT_COMMAND 0x15
#define TRANSMIT_VERSION_COMMAND 0x16
#define TRANSMIT_STATUS_COMMAND 0x17
#define TRANSMIT_LEAVE_COMMAND 0x18
#define TRANSMIT_DONATION_ADDRESS_COMMAND 0x19
#define TRANSMIT_BLOCKS_COMMAND 0x20

#include <cstdint>
#include <vector>
#include "../Block.h"

struct AskForBlocks {
    uint8_t command = ASK_FOR_BLOCKS_COMMAND;
    uint64_t startBlockHeight;
    uint64_t count;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(startBlockHeight);
        READWRITE(count);
    }
};

struct AskForBlock {
    uint8_t command = ASK_FOR_BLOCK_COMMAND;
    uint64_t blockHeight;
    std::vector<unsigned char> blockHeaderHash;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(blockHeight);
        READWRITE(blockHeaderHash);
    }
};

struct AskForPeers {
    uint8_t command = ASK_FOR_PEERS_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForBlockchainHeight {
    uint8_t command = ASK_FOR_BLOCKCHAIN_HEIGHT_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForBestBlockHeader {
    uint8_t command = ASK_FOR_BEST_BLOCK_HEADER_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForVersion {
    uint8_t command = ASK_FOR_VERSION_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForStatus {
    uint8_t command = ASK_FOR_STATUS_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForDonationAddress {
    uint8_t command = ASK_FOR_DONATION_ADDRESS_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct AskForBlocksUsingDataPacket {
    uint8_t command = ASK_FOR_BLOCKS_USING_DATA_PACKET_SIZE;
    uint32_t height;
    uint32_t offset;
    uint32_t size;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(height);
        READWRITE(offset);
        READWRITE(size);
    }
};

struct TransmitTransactions {
    uint8_t command = TRANSMIT_TRANSACTIONS_COMMAND;
    std::vector<TransactionForNetwork> transactions;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(transactions);
    }
};

struct TransmitBlock {
    uint8_t command = TRANSMIT_BLOCK_COMMAND;
    std::vector<unsigned char> block;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(block);
    }
};

struct TransmitBlocks {
    uint8_t command = TRANSMIT_BLOCKS_COMMAND;
    std::vector<std::vector<unsigned char> > blocks;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(blocks);
    }
};

struct TransmitPeers {
    uint8_t command = TRANSMIT_PEERS_COMMAND;
    std::vector<std::string> ipList;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(ipList);
    }
};

struct TransmitBlockchainHeight {
    uint8_t command = TRANSMIT_BLOCKCHAIN_HEIGHT_COMMAND;
    uint32_t height;
    std::vector<unsigned char> bestHeaderHash;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(height);
        READWRITE(bestHeaderHash);
    }
};

struct TransmitBestBlockHeader {
    uint8_t command = TRANSMIT_BEST_BLOCK_HEADER_COMMAND;
    BlockHeader header;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(header);
    }
};

struct TransmitVersion {
    uint8_t command = TRANSMIT_VERSION_COMMAND;
    uint16_t version;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(version);
    }
};

struct TransmitStatus {
    uint8_t command = TRANSMIT_STATUS_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct TransmitLeave {
    uint8_t command = TRANSMIT_LEAVE_COMMAND;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
    }
};

struct TransmitDonationAddress {
    uint8_t command = TRANSMIT_DONATION_ADDRESS_COMMAND;
    std::string donationAddress;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(command);
        READWRITE(donationAddress);
    }
};

#endif //TX_NETWORKCOMMANDS_H
