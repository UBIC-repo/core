
#ifndef TX_BLOCK_H
#define TX_BLOCK_H

#include "Transaction/Transaction.h"
#include "BlockHeader.h"

class Block {
private:
    BlockHeader header;
    std::vector<Transaction> transactions;
public:
    BlockHeader *getHeader();
    void setHeader(BlockHeader *header);
    void addTransaction(Transaction transaction);
    std::vector<Transaction> getTransactions();
    void setTransactions(std::vector<Transaction> transactions);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(transactions);
    }
};

class BlockHelper {
public:
    static bool verifyBlock(Block* block);
    static bool applyBlock(Block* block);
    static bool undoBlock(Block* block);
    static UAmount calculateDelegatePayout(uint32_t blockHeight);
    static UAmount calculateDevFundPayout(uint32_t blockHeight);
    static UAmount32 calculateUbiReceiverCount(Block* block, BlockHeader* previousBlock);
    static UAmount getTotalPayout();
    static void calculatePayout(Block* block, BlockHeader* previousBlockHeader, UAmount32 newReceiverCount, UAmount &payout, UAmount &payoutRemainder);
    static std::vector<unsigned char> computeBlockHeaderHash(BlockHeader header);
};


#endif //TX_BLOCK_H
