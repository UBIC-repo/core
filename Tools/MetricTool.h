
#ifndef UBICD_METRICTOOL_H
#define UBICD_METRICTOOL_H


#include <cstdint>

class MetricTool {
private:
    static uint64_t calculateTotalSupply(
            uint64_t emissionRate,
            uint64_t developmentEmission,
            uint64_t delegateEmission,
            uint32_t startingBlockHeight
    );
public:
    static uint64_t getPassportBlockSupply(uint8_t currencyId);
    static uint64_t getTotalSupply(uint8_t currencyId);
    static uint64_t getPassportSupply1Day(uint8_t currencyId);
};


#endif //UBICD_METRICTOOL_H
