
#ifndef TX_MINT_H
#define TX_MINT_H

#include "../Block/Block.h"

class Mint {
private:
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> publicKey;
    bool stopMint = false;
public:
    static Mint& Instance(){
        static Mint instance;
        return instance;
    }

    bool getStatus() {
        return !this->stopMint;
    }

    uint64_t getTimeStamp();
    Block mintBlock();
    void mintBlockAndBroadcast();
    void startMintingService();
    void startMinting();
    void stopMinting();
};


#endif //TX_MINT_H
