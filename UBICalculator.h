
#ifndef TX_UBICALCULATOR_H
#define TX_UBICALCULATOR_H


#include <vector>
#include "UAmount.h"
#include "AddressStore.h"
#include "Address.h"

class UBICalculator {
public:
    static bool isAddressConnectedToADSC(std::vector<unsigned char> address);
    static bool isAddressConnectedToADSC(AddressForStore* address);
    static UAmount totalReceivedUBI(std::vector<unsigned char> address);
    static UAmount totalReceivedUBI(std::vector<unsigned char> address, uint32_t blockHeight);
    static UAmount totalReceivedUBI(AddressForStore* addressForStore);
    static UAmount totalReceivedUBI(AddressForStore* addressForStore, uint32_t blockHeight);
};


#endif //TX_UBICALCULATOR_H
