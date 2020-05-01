
#include "DSCAttachedPassportCounter.h"
#include "DB/DB.h"
#include "ChainParams.h"
#include "Serialization/streams.h"
#include "Tools/Log.h"

bool DSCAttachedPassportCounter::increment(std::vector<unsigned char> dscId) {
    DB& db = DB::Instance();

    std::vector<unsigned char> dscCountVector = db.getFromDB(DB_DSC_ATTACHED_PASSPORTS_COUNTER, dscId);
    DSCAttachedPassportCount dscAttachedPassportCount;

    if(dscCountVector.size()) {
        CDataStream s(SER_DISK, 1);
        s.write((char*)dscCountVector.data(), dscCountVector.size());
        s >> dscAttachedPassportCount;
        dscAttachedPassportCount++;
    } else {
        dscAttachedPassportCount.count = 1;
    }

    CDataStream s2(SER_DISK, 1);
    s2 << dscAttachedPassportCount;

    db.putInDB(DB_DSC_ATTACHED_PASSPORTS_COUNTER, dscId, std::vector<unsigned char> (s2.data(), s2.data() + s2.size()));

    return true;
}

bool DSCAttachedPassportCounter::decrement(std::vector<unsigned char> dscId) {
    DB& db = DB::Instance();

    std::vector<unsigned char> dscCountVector = db.getFromDB(DB_DSC_ATTACHED_PASSPORTS_COUNTER, dscId);
    DSCAttachedPassportCount dscAttachedPassportCount;

    if(!dscCountVector.size()) {
        Log(LOG_LEVEL_ERROR) << "Cannot decrement not existing DB_DSC_ATTACHED_PASSPORTS_COUNTER entry" << dscId;
        return false;
    }

    CDataStream s(SER_DISK, 1);
    s.write((char*)dscCountVector.data(), dscCountVector.size());
    s >> dscAttachedPassportCount;

    if(dscAttachedPassportCount.count == 0) {
        Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot decrement DB_DSC_ATTACHED_PASSPORTS_COUNTER, entry is already 0" << dscId;
        return false;
    }

    dscAttachedPassportCount--;

    CDataStream s2(SER_DISK, 1);
    s2 << dscAttachedPassportCount;

    db.putInDB(DB_DSC_ATTACHED_PASSPORTS_COUNTER, dscId, std::vector<unsigned char> (s2.data(), s2.data() + s2.size()));

    return true;
}

uint64_t DSCAttachedPassportCounter::getCount(std::vector<unsigned char> dscId) {
    DB& db = DB::Instance();

    std::vector<unsigned char> dscCountVector = db.getFromDB(DB_DSC_ATTACHED_PASSPORTS_COUNTER, dscId);
    DSCAttachedPassportCount dscAttachedPassportCount;

    if(dscCountVector.size()) {
        CDataStream s(SER_DISK, 1);
        s.write((char*)dscCountVector.data(), dscCountVector.size());
        s >> dscAttachedPassportCount;
        return dscAttachedPassportCount.count;
    }

    return 0;
}