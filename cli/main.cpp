#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "HttpClient.h"
#include "ApiKey.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Missing parameter, options are: status, start-minting, stop-minting" << std::endl;
        return 0;
    }

    HttpClient *client = new HttpClient();
    std::string response;

    // --- Status
    if (strcmp(argv[1], "status") == 0) {
        response = client->get("/", ApiKey::getApiKey());
	if(response.empty()) {
		return 0;
	}

        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);

        std::string height;
        std::string hash;
        std::string synced;

        for (boost::property_tree::ptree::value_type &v : pt) {
            if (strcmp(v.first.data(), "bestBlock") == 0) {
                for (boost::property_tree::ptree::value_type &v2 : v.second) {
                    if (strcmp(v2.first.data(), "hash") == 0) {
                        hash = v2.second.data();
                    }

                    if (strcmp(v2.first.data(), "height") == 0) {
                        height = v2.second.data();
                    }
                }
            }
            if (strcmp(v.first.data(), "synced") == 0) {
                synced = v.second.data();
            }
        }

        std::cout << "Synced: " << synced << std::endl;
        std::cout << "Blockchain height: " << height << std::endl;
        std::cout << "Best block hash: " << hash << std::endl;
    }

    // --- Stop minting
    if (strcmp(argv[1], "stop-minting") == 0) {
        response = client->get("/mint/stop", ApiKey::getApiKey());
	if(response.empty()) {
		return 0;
	}

        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);

        for (boost::property_tree::ptree::value_type &v : pt) {
            if (strcmp(v.first.data(), "done") == 0 && strcmp(v.first.data(), "done") == 0) {
                std::cout << "Stopped minting" << std::endl;
            }
        }
    }


    // --- Start minting
    if (strcmp(argv[1], "stop-minting") == 0) {
        response = client->get("/mint/start", ApiKey::getApiKey());
	if(response.empty()) {
		return 0;
	}

        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);

        for (boost::property_tree::ptree::value_type &v : pt) {
            if (strcmp(v.first.data(), "done") == 0 && strcmp(v.first.data(), "done") == 0) {
                std::cout << "Started minting" << std::endl;
            }
        }
    }

    // --- Balance
/*
    response = client->get("/wallet", ApiKey::getApiKey());
    std::cout << response << std::endl;
*/

    return 0;
}
