
#include <boost/property_tree/ini_parser.hpp>
#include "Config.h"
#include "FS/FS.h"
#include "App.h"

bool Config::loadConfig() {
    char path[512];
    FS::charPathFromVectorPath(path, FS::getConfigPath());

    //Log(LOG_LEVEL_INFO) << "FS::readFile(FS::getConfigPath()):" << FS::readFile(FS::getConfigPath());
    try {
        boost::property_tree::ptree pt;
        boost::property_tree::ini_parser::read_ini(path, pt);
        this->blockchainPath = pt.get<std::string>("blockchainPath");
        this->allowFrom = pt.get<std::string>("allowFrom");
        this->donationAddress = pt.get<std::string>("donationAddress");
        this->apiKey = pt.get<std::string>("apiKey");
        this->numberOfAdresses = (uint32_t)std::stoi(pt.get<std::string>("numberOfAdresses"));
        this->mintingStatus = pt.get<std::string>("minting");

        this->logLevel = LOG_LEVEL_INFO;
        if(pt.get<std::string>("logLevel") == "NOTICE") {
            this->logLevel = LOG_LEVEL_NOTICE;
        } else if(pt.get<std::string>("logLevel") == "INFO") {
            this->logLevel = LOG_LEVEL_INFO;
        } else if(pt.get<std::string>("logLevel") == "WARNING") {
            this->logLevel = LOG_LEVEL_WARNING;
        } else if(pt.get<std::string>("logLevel") == "ERROR") {
            this->logLevel = LOG_LEVEL_ERROR;
        } else if(pt.get<std::string>("logLevel") == "CRITICAL") {
            this->logLevel = LOG_LEVEL_CRITICAL_ERROR;
        }


    } catch (const std::exception& e) {
        Log(LOG_LEVEL_ERROR) << "Config::loadConfig() exception:" << e.what();
        App &app = App::Instance();
        app.immediateTerminate();
        return false;
    }

    return true;
}

std::string Config::getBlockchainPath() {
    return this->blockchainPath;
}

std::string Config::getAllowFrom() {
    return this->allowFrom;
}

uint32_t Config::getNumberOfAdresses() {
    return this->numberOfAdresses;
}

uint8_t Config::getLogLevel() {
    return this->logLevel;
}

std::string Config::getDonationAddress() {
    return this->donationAddress;
}

std::string Config::getApiKey() {
    return this->apiKey;
}

bool Config::isMintingEnabled() {
    return this->mintingStatus.compare("ON") == 0 || this->mintingStatus.compare("on") == 0;
}
