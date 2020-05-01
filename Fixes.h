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
};


#endif //UBICD_FIXES_H
