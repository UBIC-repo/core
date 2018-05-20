

#ifndef TX_API_H
#define TX_API_H


#include <vector>
#include <string>

class Api {
public:

    static std::string vote(std::string json);
    static std::string unvote(std::string json);
    static std::string getDelegates();
    static std::string removePeer(std::string json);
    static std::string addPeer(std::string json);
    static std::string getPeers();

    static std::string getAddress(std::vector<unsigned char> address);
    static std::string removeBan(std::string json);
    static std::string addBan(std::string json);
    static std::string getBans();
    static std::string myTransactions();
    static std::string readPassport(std::string json);
    static std::string pay(std::string json);
    static std::string createTransaction(std::string json);
    static std::string sendTransaction(std::string json);
    static std::string startMint();
    static std::string stopMint();
    static std::string mintStatus();
    static std::string getUbi();
    static std::string getWallet();
    static std::string getTxPool();
    static std::string getFees();
    static std::string getIncomingTx();
    static std::string getBlock(uint32_t blockHeight);
    static std::string getBlock(std::vector<unsigned char> blockHeaderHash);
    static std::string getIndex();
    static std::string getRootCertificates();
    static std::string getCSCACertificates();
    static std::string getDSCCertificate(std::string dscIdString);
    static std::string getDSCCertificates();
    static std::string addCert(std::string json, uint8_t type);
    static std::string removeCert(std::string json, uint8_t type);
};


#endif //TX_API_H
