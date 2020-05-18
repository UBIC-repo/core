
#ifndef TX_ADDRESSSTORE_H
#define TX_ADDRESSSTORE_H

#include "Address.h"
#include "Block/BlockHeader.h"

class AddressStore {
public:
    static AddressStore& Instance(){
        static AddressStore instance;
        return instance;
    }

    void debitAddressToStore(std::vector<unsigned char> addressKey, UAmount amount, BlockHeader* blockHeader, bool isUndo);
    void debitAddressToStore(AddressForStore* address, UAmount amount, bool isUndo);
    void creditAddressToStore(AddressForStore* address, bool isUndo);
    static AddressForStore getAddressFromStore(const std::vector<unsigned char> &address);
};


#endif //TX_ADDRESSSTORE_H
