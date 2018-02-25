
#include "MerkleTree.h"
#include "streams.h"
#include "Crypto/Sha256.h"
#include "ChainParams.h"

/*
 * @TODO Test this code, write unit tests
 */
std::vector<unsigned char> MerkleTree::computeMerkleTreeRootValue(std::vector<Transaction> transactions) {

    if(transactions.size() == 0) {
        return std::vector<unsigned char>();
    }

    std::vector<std::vector<unsigned char> > leaves;

    for(Transaction transaction: transactions) {
        CDataStream s(SER_DISK, SERIALIZATION_VERSION);
        s << transaction;

        leaves.emplace_back(Sha256::sha256(std::vector<unsigned char>(s.data(), s.data() + s.size())));
    }

    while(leaves.size() > 1) {
        std::vector<std::vector<unsigned char> > newLeaves;
        while(leaves.size() > 0) {
            if (leaves.size() == 1) {
                newLeaves.emplace_back((std::vector<unsigned char>)leaves.back());
                leaves.pop_back();
            } else if(leaves.size() > 1) {
                std::vector<unsigned char> leave1 = (std::vector<unsigned char>)leaves.back();
                leaves.pop_back();
                std::vector<unsigned char> leave2 = (std::vector<unsigned char>)leaves.back();
                leaves.pop_back();

                leave1.insert( leave1.end(), leave2.begin(), leave2.end() ); // concat leaves

                newLeaves.emplace_back(Sha256::sha256(leave1));
            }

        }

        leaves = newLeaves;
    }

    return leaves.at(0);
}

bool MerkleTree::verifyMerkleTreeRootValue(std::vector<Transaction> transactions, std::vector<unsigned char> merkleRoot) {
    std::vector<unsigned char> calculatedMerkleRoot = MerkleTree::computeMerkleTreeRootValue(transactions);

    return calculatedMerkleRoot == merkleRoot;
}