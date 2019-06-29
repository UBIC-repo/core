
#ifndef TX_WALLET_H
#define TX_WALLET_H

#include <string>
#include <openssl/ec.h>
#include "Address.h"
#include "Transaction/Transaction.h"

class Wallet {
private:
    std::vector<unsigned char> seed;
    std::vector< std::vector<unsigned char> > privateKeys;
    std::vector< std::vector<unsigned char> > publicKeys;
    std::vector< std::vector<unsigned char> > addressesScript;
    std::vector< std::vector<unsigned char> > addressesLink;
    bool generateWallet();
public:
    static Wallet& Instance(){
        static Wallet instance;
        return instance;
    }
    bool initWallet();
    bool loadSeedFromFS();
    bool persistSeedToFS();
    UAmount getBalance();
    std::vector<unsigned char> generateSeed();

    std::vector<std::vector<unsigned char> > getAddressesScript();
    std::vector<std::vector<unsigned char> > getAddressesLink();
    std::vector<unsigned char> signWithAddress(std::vector<unsigned char> address, std::vector<unsigned char> msg);
    std::vector<unsigned char> getRandomPrivateKeyFromWallet();
    std::vector<unsigned char> getRandomAddressScriptVectorFromWallet();
    Address getRandomAddressFromWallet();
    Transaction* signTransaction(Transaction* transaction);
    Transaction* payToTxOutputs(std::vector<TxOut> txOutputs);
    Transaction* payToTxOutputsWithoutFees(std::vector<TxOut> txOutputs);
    UScript getRandomPKHScriptFromWallet();
    bool isMine(UScript script);
    bool isMine(std::vector<unsigned char> scriptLink);
    std::vector<unsigned char> getPublicKeyFromAddressLink(std::vector<unsigned char> address);
    static Address addressFromPublicKey(std::vector<unsigned char> publicKey);
    static Address addressFromPrivateKey(EVP_PKEY *privateKey);
    static std::vector<unsigned char> addressVectorFromAddress(Address address);
    static std::string readableAddressFromAddress(Address address);
    static std::vector<unsigned char> readableAddressToVectorAddressWithChecksum(std::string readableAddress);
    static std::vector<unsigned char> readableAddressToVectorAddress(std::string readableAddress);
    static void readableAddresstoCharAddress(std::string readableAddress, unsigned char* address, uint8_t *addressLength);
    static bool verifyReadableAddressChecksum(std::string readableAddress);
    static EC_GROUP *getDefaultEcGroup();
    static bool generatePrivateKey(EVP_PKEY* privateKey);
    static bool privateKeyFromVector(EVP_PKEY* privateKey, std::vector<unsigned char> privateVector);
    std::vector<TransactionForStore> getMyTransactions();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(privateKeys);
        READWRITE(publicKeys);
        READWRITE(addressesScript);
        READWRITE(addressesLink);
    }
};


#endif //TX_WALLET_H
