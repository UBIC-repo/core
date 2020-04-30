
#ifndef TX_MERKLETREE_H
#define TX_MERKLETREE_H


#include <vector>
#include "Transaction/Transaction.h"

class MerkleTree {
public:
    static std::vector<unsigned char> computeMerkleTreeRootValue(std::vector<Transaction> transactions);
    static bool verifyMerkleTreeRootValue(std::vector<Transaction> transactions, std::vector<unsigned char> merkleRoot);
};

#endif //TX_MERKLETREE_H
