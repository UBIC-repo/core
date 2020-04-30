#ifndef UBICD_TRANSACTIONAPPLY_H
#define UBICD_TRANSACTIONAPPLY_H


#include "Transaction.h"
#include "../BlockHeader.h"

class TransactionApply {
public:
    static bool applyTransaction(Transaction* tx, BlockHeader* blockHeader);
    static bool undoTransaction(Transaction* tx, BlockHeader* blockHeader);
};


#endif //UBICD_TRANSACTIONAPPLY_H
