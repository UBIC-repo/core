
#include <iostream>
#include "ApiKey.h"
#include "FS/FS.h"
#include <boost/asio.hpp>
#include <thread>
#include <regex>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ini_parser.hpp>

std::string ApiKey::getApiKey() {
    char path[512];
    FS::charPathFromVectorPath(path, FS::getConfigPath());

    try {
        boost::property_tree::ptree pt;
        boost::property_tree::ini_parser::read_ini(path, pt);
        return pt.get<std::string>("apiKey");

    } catch (const std::exception& e) {
        std::cout << "Config::loadConfig() exception:" << e.what();
        return "";
    }

}