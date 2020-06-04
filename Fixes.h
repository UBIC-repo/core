/**
 * Mistakes can happen, this class intends to fix them
 */

#ifndef UBICD_FIXES_H
#define UBICD_FIXES_H

#include <cstdint>
#include <vector>

class Fixes {
public:
    // fixes certificates with wrong currency ID
    static uint8_t fixCertificateCurrencyID(std::vector<unsigned char> certificateID, uint8_t currencyID);
    static bool ignorePaddingForThisPassport(std::vector<unsigned char> passportHash);
    static uint16_t fixWrongHashAlg(std::vector<unsigned char> passportHash, uint16_t mdAlg);
};


#endif //UBICD_FIXES_H
