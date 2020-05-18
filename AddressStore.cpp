
#include "AddressStore.h"
#include "DB/DB.h"
#include "Tools/Log.h"
#include "AddressHelper.h"

void AddressStore::debitAddressToStore(std::vector<unsigned char> addressKey, UAmount amount, BlockHeader* blockHeader, bool isUndo) {
    AddressForStore address = getAddressFromStore(addressKey);
    this->debitAddressToStore(&address, amount, isUndo);
}

void AddressStore::debitAddressToStore(AddressForStore* address, UAmount amount, bool isUndo) {
    DB& db = DB::Instance();
    Log(LOG_LEVEL_INFO) << "Amount to debit: " << amount;

    if(!(address->getAmount() >= amount)) {
        // If we are spending more than our balance debit from UBI grants

        UAmount debit;
        for(std::map<uint8_t, CAmount>::iterator it = amount.map.begin(); it != amount.map.end(); it++) {
            Log(LOG_LEVEL_INFO) << "it->second: " << (uint32_t)it->first;
            if(it->second > address->getAmount().map[it->first]) {
                debit.map.insert(std::pair<uint8_t, CAmount>(it->first, it->second - address->getAmount().map[it->first]));
            }
        }
        Log(LOG_LEVEL_INFO) << "will debit: " << debit;
        Log(LOG_LEVEL_INFO) << "setUBIdebit: " << address->getUBIdebit() + debit;
        address->setUBIdebit(address->getUBIdebit() + debit);
        amount = amount - debit;
    }

    UAmount finalAmount = address->getAmount() - amount;
    address->setAmount(finalAmount);
    if(!isUndo) {
        address->setNonce(address->getNonce() + 1);
    }

    Log(LOG_LEVEL_INFO) << "new address nonce: " << address->getNonce();

    db.serializeToDb(DB_ADDRESS_STORE, AddressHelper::addressLinkFromScript(address->getScript()), *address);
}

void AddressStore::creditAddressToStore(AddressForStore* address, bool isUndo) {

    std::vector<unsigned char> addressKey = AddressHelper::addressLinkFromScript(address->getScript());
    AddressForStore currentAddress = getAddressFromStore(
            addressKey
    );

    UAmount finalAmount = address->getAmount() + currentAddress.getAmount();
    currentAddress.setAmount(finalAmount);
    if(isUndo) {
        currentAddress.setNonce((currentAddress.getNonce() - 1));
        Log(LOG_LEVEL_INFO) << "UNDO: updated nonce from "
                            << currentAddress.getNonce() + 1
                            << " to "
                            << currentAddress.getNonce()
                            << " for address:"
                            << addressKey;
    }

    if(currentAddress.getScript().getScript().empty()) {
        currentAddress.setScript(address->getScript());
    }

    if(!address->getDscToAddressLinks().empty()) {
        std::vector<DscToAddressLink> currentDscToAddressLinks = currentAddress.getDscToAddressLinks();
        std::vector<DscToAddressLink> newDscToAddressLinks = address->getDscToAddressLinks();

        auto it = newDscToAddressLinks.begin();
        while (it != newDscToAddressLinks.end()) {
            currentDscToAddressLinks.push_back(*it);
            it++;
        }

        currentAddress.setDscToAddressLinks(currentDscToAddressLinks);
    }

    DB& db = DB::Instance();

    db.serializeToDb(DB_ADDRESS_STORE, addressKey, currentAddress);
    Log(LOG_LEVEL_INFO) << "Credited address " << addressKey;
}

AddressForStore AddressStore::getAddressFromStore(const std::vector<unsigned char> &address) {
    AddressForStore addressForStore;
    addressForStore.setNonce(0); //default nonce if not in address store
    DB& db = DB::Instance();
    db.deserializeFromDb(DB_ADDRESS_STORE, address, addressForStore);

    return addressForStore;
}
