
#ifndef TX_ADDRESSHELPER_H
#define TX_ADDRESSHELPER_H

#include "UAmount.h"
#include "UBICalculator.h"

class AddressHelper {
public:

    static std::vector<unsigned char> addressLinkFromScript(UScript script) {
        //if it is already an address
        if(script.getScriptType() == SCRIPT_LINK) {
            return script.getScript();
        }
        CDataStream s(SER_DISK, 1);
        s << script;
        std::vector<unsigned char> r(s.data(), s.data() + s.size());

        return Hash160::hash160(r);
    }

    static UAmount getAmountWithUBI(AddressForStore* addressForStore) {
        if(UBICalculator::isAddressConnectedToADSC(addressForStore)) {
            return addressForStore->getAmount() + UBICalculator::totalReceivedUBI(addressForStore) - addressForStore->getUBIdebit();
        }
        return addressForStore->getAmount();
    }
};

#endif //TX_ADDRESSHELPER_H
