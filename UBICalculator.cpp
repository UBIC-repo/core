
#include "UBICalculator.h"
#include "CertStore/CertStore.h"
#include "Chain.h"
#include "PathSum/PathSum.h"
#include "Tools/Log.h"

bool UBICalculator::isAddressConnectedToADSC(std::vector<unsigned char> address) {
    AddressStore& addressStore = AddressStore::Instance();
    AddressForStore addressForStore = addressStore.getAddressFromStore(address);
    return UBICalculator::isAddressConnectedToADSC(&addressForStore);
}

bool UBICalculator::isAddressConnectedToADSC(AddressForStore* address) {
    if(address->getDSCLinkedAtHeight()) {
        return true;
    }
    return false;
}

UAmount UBICalculator::totalReceivedUBI(std::vector<unsigned char> address) {
    Chain& chain = Chain::Instance();

    return UBICalculator::totalReceivedUBI(address, chain.getCurrentBlockchainHeight());
}

UAmount UBICalculator::totalReceivedUBI(std::vector<unsigned char> address, uint32_t blockHeight) {

    CertStore& certStore = CertStore::Instance();
    AddressStore& addressStore = AddressStore::Instance();
    AddressForStore addressForStore = addressStore.getAddressFromStore(address);

    return UBICalculator::totalReceivedUBI(&addressForStore, blockHeight);
}

UAmount UBICalculator::totalReceivedUBI(AddressForStore* addressForStore) {
    Chain& chain = Chain::Instance();

    return UBICalculator::totalReceivedUBI(addressForStore, chain.getCurrentBlockchainHeight());
}

UAmount UBICalculator::totalReceivedUBI(AddressForStore* addressForStore, uint32_t blockHeight) {

    CertStore& certStore = CertStore::Instance();

    uint32_t startHeight = addressForStore->getDSCLinkedAtHeight();

    Cert* cert = certStore.getDscCertWithCertId(addressForStore->getDscCertificate());
    std::vector<std::pair<uint32_t , bool> > statusList = cert->getStatusList();
    std::vector<std::pair<uint32_t, uint32_t > > newStatusList;
    std::vector<std::pair<uint32_t, bool> >::const_iterator statusIterator = statusList.begin();

    // only one element in statusList
    if(statusIterator == statusList.end()) {
        std::pair<uint32_t, uint32_t > currentPair(0,0);
        currentPair = std::pair<uint32_t, uint32_t>(statusIterator->first, blockHeight);
        if(statusIterator->second) { // only if is active status
            newStatusList.emplace_back(currentPair);
        }
    } else {
        // several elements in statusList
        while (statusIterator != statusList.end()) {
            std::pair<uint32_t, uint32_t> currentPair(0, 0);
            currentPair.first = statusIterator->first;
            bool isActive = statusIterator->second;
            statusIterator++;
            if (statusIterator == statusList.end()) {
                currentPair.second = blockHeight;
            } else {
                currentPair.second = statusIterator->first;
            }

            if(isActive) { // only if is active status
                newStatusList.emplace_back(currentPair);
            }
        }
    }

    UAmount totalAmount;
    PathSum& pathSum = PathSum::Instance();

    for(std::pair<uint32_t, uint32_t> pair : newStatusList) {
        Log(LOG_LEVEL_INFO) << "PAIR: " << pair.first << ", " << pair.second << " START: " << startHeight;
        if(startHeight > pair.second) {
            //do nothing
        } else if(startHeight > pair.first) {
            // take pair between startHeight and pair.second
            totalAmount.map[cert->getCurrencyId()] += pathSum.getSum(startHeight, pair.second).map[cert->getCurrencyId()]; // @TODO can be performance optimized
        } else if(startHeight < pair.first) {
            //take entire pair
            totalAmount.map[cert->getCurrencyId()] += pathSum.getSum(pair.first, pair.second).map[cert->getCurrencyId()];
        }
    }

    Log(LOG_LEVEL_INFO) << "UBI sum: " << totalAmount;

    return totalAmount;
}