
#include "MetricTool.h"
#include "../ChainParams.h"
#include "../Chain.h"

uint64_t MetricTool::calculateTotalSupply(
        uint64_t emissionRate,
        uint64_t developmentEmission,
        uint64_t delegateEmission,
        uint32_t startingBlockHeight
) {
    Chain &chain = Chain::Instance();
    uint32_t currentBlockchainHeight = chain.getCurrentBlockchainHeight();

    uint64_t total = 0;
    if(currentBlockchainHeight > startingBlockHeight) {
        total += (emissionRate * (currentBlockchainHeight - startingBlockHeight));
        total += (delegateEmission * (currentBlockchainHeight - startingBlockHeight));

        uint64_t halvingFactor = 1;
        for(int i = 0; i < NUMBER_OF_HALVINGS; i++) {
            if((uint32_t)(HALVING_INTERVAL_IN_BLOCKS * i) < currentBlockchainHeight) {
                uint32_t endBlockHeight = ((uint32_t)(HALVING_INTERVAL_IN_BLOCKS * (i + 1)) > currentBlockchainHeight)
                                          ? currentBlockchainHeight : HALVING_INTERVAL_IN_BLOCKS * (i + 1);
                if (endBlockHeight > startingBlockHeight) {
                    total += ((developmentEmission / halvingFactor) * (endBlockHeight - startingBlockHeight));
                }
                halvingFactor = halvingFactor * 2;
            }
        }
    }

    return total;
}

uint64_t MetricTool::getPassportBlockSupply(uint8_t currencyId) {
    Chain &chain = Chain::Instance();
    BlockHeader* header = chain.getBestBlockHeader();
    if(header != nullptr) {
        UAmount payout = header->getPayout();
        for(std::map<uint8_t, CAmount>::iterator it = payout.map.begin(); it != payout.map.end(); it++) {
            if(it->first == currencyId) {
                return it->second;
            }
        }
    }

    return 0;
}

uint64_t MetricTool::getTotalSupply(uint8_t currencyId) {
    if(currencyId == CURRENCY_SWITZERLAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_SWITZERLAND_EMISSION_RATE,
                CURRENCY_SWITZERLAND_DEVELOPMENT_PAYOUT,
                CURRENCY_SWITZERLAND_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_GERMANY) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_GERMANY_EMISSION_RATE,
                CURRENCY_GERMANY_DEVELOPMENT_PAYOUT,
                CURRENCY_GERMANY_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_AUSTRIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_AUSTRIA_EMISSION_RATE,
                CURRENCY_AUSTRIA_DEVELOPMENT_PAYOUT,
                CURRENCY_AUSTRIA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_UNITED_KINGDOM) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_UNITED_KINGDOM_EMISSION_RATE,
                CURRENCY_UNITED_KINGDOM_DEVELOPMENT_PAYOUT,
                CURRENCY_UNITED_KINGDOM_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_IRELAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_IRELAND_EMISSION_RATE,
                CURRENCY_IRELAND_DEVELOPMENT_PAYOUT,
                CURRENCY_IRELAND_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_USA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_USA_EMISSION_RATE,
                CURRENCY_USA_DEVELOPMENT_PAYOUT,
                CURRENCY_USA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_AUSTRALIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_AUSTRALIA_EMISSION_RATE,
                CURRENCY_AUSTRALIA_DEVELOPMENT_PAYOUT,
                CURRENCY_AUSTRALIA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_CHINA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_CHINA_EMISSION_RATE,
                CURRENCY_CHINA_DEVELOPMENT_PAYOUT,
                CURRENCY_CHINA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_SWEDEN) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_SWEDEN_EMISSION_RATE,
                CURRENCY_SWEDEN_DEVELOPMENT_PAYOUT,
                CURRENCY_SWEDEN_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_FRANCE) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_FRANCE_EMISSION_RATE,
                CURRENCY_FRANCE_DEVELOPMENT_PAYOUT,
                CURRENCY_FRANCE_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_CANADA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_CANADA_EMISSION_RATE,
                CURRENCY_CANADA_DEVELOPMENT_PAYOUT,
                CURRENCY_CANADA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_JAPAN) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_JAPAN_EMISSION_RATE,
                CURRENCY_JAPAN_DEVELOPMENT_PAYOUT,
                CURRENCY_JAPAN_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_THAILAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_THAILAND_EMISSION_RATE,
                CURRENCY_THAILAND_DEVELOPMENT_PAYOUT,
                CURRENCY_THAILAND_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_NEW_ZEALAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_NEW_ZEALAND_EMISSION_RATE,
                CURRENCY_NEW_ZEALAND_DEVELOPMENT_PAYOUT,
                CURRENCY_NEW_ZEALAND_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_UNITED_ARAB_EMIRATES) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_UNITED_ARAB_EMIRATES_EMISSION_RATE,
                CURRENCY_UNITED_ARAB_EMIRATES_DEVELOPMENT_PAYOUT,
                CURRENCY_UNITED_ARAB_EMIRATES_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_FINLAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_FINLAND_EMISSION_RATE,
                CURRENCY_FINLAND_DEVELOPMENT_PAYOUT,
                CURRENCY_FINLAND_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_LUXEMBOURG) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_LUXEMBOURG_EMISSION_RATE,
                CURRENCY_LUXEMBOURG_DEVELOPMENT_PAYOUT,
                CURRENCY_LUXEMBOURG_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_SINGAPORE) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_SINGAPORE_EMISSION_RATE,
                CURRENCY_SINGAPORE_DEVELOPMENT_PAYOUT,
                CURRENCY_SINGAPORE_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_HUNGARY) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_HUNGARY_EMISSION_RATE,
                CURRENCY_HUNGARY_DEVELOPMENT_PAYOUT,
                CURRENCY_HUNGARY_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_CZECH_REPUBLIC) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_CZECH_REPUBLIC_EMISSION_RATE,
                CURRENCY_CZECH_REPUBLIC_DEVELOPMENT_PAYOUT,
                CURRENCY_CZECH_REPUBLIC_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_MALAYSIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_MALAYSIA_EMISSION_RATE,
                CURRENCY_MALAYSIA_DEVELOPMENT_PAYOUT,
                CURRENCY_MALAYSIA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_UKRAINE) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_UKRAINE_EMISSION_RATE,
                CURRENCY_UKRAINE_DEVELOPMENT_PAYOUT,
                CURRENCY_UKRAINE_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_ESTONIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_ESTONIA_EMISSION_RATE,
                CURRENCY_ESTONIA_DEVELOPMENT_PAYOUT,
                CURRENCY_ESTONIA_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_MONACO) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_MONACO_EMISSION_RATE,
                CURRENCY_MONACO_DEVELOPMENT_PAYOUT,
                CURRENCY_MONACO_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_LIECHTENSTEIN) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_LIECHTENSTEIN_EMISSION_RATE,
                CURRENCY_LIECHTENSTEIN_DEVELOPMENT_PAYOUT,
                CURRENCY_LIECHTENSTEIN_DELEGATE_PAYOUT,
                0
        );
    }

    if(currencyId == CURRENCY_ICELAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_ICELAND_EMISSION_RATE,
                CURRENCY_ICELAND_DEVELOPMENT_PAYOUT,
                CURRENCY_ICELAND_DELEGATE_PAYOUT,
                ICELAND_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_SPAIN) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_SPAIN_EMISSION_RATE,
                CURRENCY_SPAIN_DEVELOPMENT_PAYOUT,
                CURRENCY_SPAIN_DELEGATE_PAYOUT,
                SPAIN_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_RUSSIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_RUSSIA_EMISSION_RATE,
                CURRENCY_RUSSIA_DEVELOPMENT_PAYOUT,
                CURRENCY_RUSSIA_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_ISRAEL) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_ISRAEL_EMISSION_RATE,
                CURRENCY_ISRAEL_DEVELOPMENT_PAYOUT,
                CURRENCY_ISRAEL_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_PORTUGAL) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_PORTUGAL_EMISSION_RATE,
                CURRENCY_PORTUGAL_DEVELOPMENT_PAYOUT,
                CURRENCY_PORTUGAL_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_DENMARK) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_DENMARK_EMISSION_RATE,
                CURRENCY_DENMARK_DEVELOPMENT_PAYOUT,
                CURRENCY_DENMARK_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_TURKEY) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_TURKEY_EMISSION_RATE,
                CURRENCY_TURKEY_DEVELOPMENT_PAYOUT,
                CURRENCY_TURKEY_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_ROMANIA) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_ROMANIA_EMISSION_RATE,
                CURRENCY_ROMANIA_DEVELOPMENT_PAYOUT,
                CURRENCY_ROMANIA_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_POLAND) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_POLAND_EMISSION_RATE,
                CURRENCY_POLAND_DEVELOPMENT_PAYOUT,
                CURRENCY_POLAND_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_NETHERLANDS) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_NETHERLANDS_EMISSION_RATE,
                CURRENCY_NETHERLANDS_DEVELOPMENT_PAYOUT,
                CURRENCY_NETHERLANDS_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_0_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_PHILIPPINES) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_PHILIPPINES_EMISSION_RATE,
                CURRENCY_PHILIPPINES_DEVELOPMENT_PAYOUT,
                CURRENCY_PHILIPPINES_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_1_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_ITALY) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_ITALY_EMISSION_RATE,
                CURRENCY_ITALY_DEVELOPMENT_PAYOUT,
                CURRENCY_ITALY_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_1_ACTIVATION_BLOCK_HEIGHT
        );
    }

    if(currencyId == CURRENCY_BRAZIL) {
        return MetricTool::calculateTotalSupply(
                CURRENCY_BRAZIL_EMISSION_RATE,
                CURRENCY_BRAZIL_DEVELOPMENT_PAYOUT,
                CURRENCY_BRAZIL_DELEGATE_PAYOUT,
                NEW_COUNTRIES_BATCH_1_ACTIVATION_BLOCK_HEIGHT
        );
    }

    return 0;
}

uint64_t MetricTool::getPassportSupply1Day(uint8_t currencyId) {
    Chain &chain = Chain::Instance();

    // first we calculate the number of blocks produced in the last 24 hours
    BlockHeader* header = chain.getBestBlockHeader();
    if(header == nullptr) {
        return 0;
    }

    uint64_t firstHeaderTimestamp = header->getTimestamp();
    uint32_t headersInLast24Hrs = 1;

    do {
        header = chain.getBlockHeader(header->getPreviousHeaderHash());
        if(header == nullptr) {
            return 0;
        }

        headersInLast24Hrs++;
    } while(header->getTimestamp() > firstHeaderTimestamp - (24*60*60));

    return getPassportBlockSupply(currencyId) * headersInLast24Hrs;
}