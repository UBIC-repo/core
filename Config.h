
#ifndef TX_CONFIG_H
#define TX_CONFIG_H


#include <string>

class Config {
private:
    std::string blockchainPath;
    std::string allowFrom;
    std::string donationAddress;
    std::string apiKey;
    std::string mintingStatus;
    uint32_t numberOfAdresses;
    uint8_t logLevel;
public:
    static Config& Instance(){
        static Config instance;
        return instance;
    }

    bool loadConfig();

    std::string getBlockchainPath();
    std::string getAllowFrom();
    uint32_t getNumberOfAdresses();
    uint8_t getLogLevel();
    std::string getDonationAddress();
    std::string getApiKey();
    bool isMintingEnabled();
};


#endif //TX_CONFIG_H
