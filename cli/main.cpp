#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "HttpClient.h"
#include "ApiKey.h"

using boost::property_tree::ptree;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Missing parameter, options are: web, status, start-minting, stop-minting, add-peer, peers, reindex" << std::endl;
        return 0;
    }

    HttpClient *client = new HttpClient();
    std::string response;

    // --- Web interface
    if (strcmp(argv[1], "web") == 0) {
        std::cout << "Web interface: http://127.0.01:6789#" << ApiKey::getApiKey() << std::endl;

        return 0;
    }

    // --- Status
    if (strcmp(argv[1], "status") == 0) {
        response = client->get("/", ApiKey::getApiKey());
        if(response.empty()) {
            return 0;
        }

        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);

        std::string height = "?";
        std::string hash = "?";
        std::string synced = "?";
        std::string peersCount = "?";

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
            if (strcmp(v.first.data(), "peersCount") == 0) {
                peersCount = v.second.data();
            }
        }

        std::cout << "Synced: " << synced << std::endl;
        std::cout << "Blockchain height: " << height << std::endl;
        std::cout << "Best block hash: " << hash << std::endl;
        std::cout << "Connected to " << peersCount << " peer(s)" << std::endl;

        return 0;
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
            if (strcmp(v.first.data(), "done") == 0) {
                std::cout << "Stopped minting" << std::endl;
            }
        }

        return 0;
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
            if (strcmp(v.first.data(), "done") == 0) {
                std::cout << "Started minting" << std::endl;
            }
        }

        return 0;
    }

    // --- add peer
    if (strcmp(argv[1], "add-peer") == 0) {
        if(argc < 3) {
            std::cout << "Missing IP parameter" << std::endl;
        }
        std::stringstream ss;
        ss << "{\"ip\":\"" << argv[2] << "\"}";

        response = client->post("/peers/add", ApiKey::getApiKey(), HttpClient::url_encode(ss.str()));
        if(response.empty()) {
            return 0;
        }

        std::stringstream ss2(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss2, pt);

        for (boost::property_tree::ptree::value_type &v : pt) {
            if (strcmp(v.first.data(), "success") == 0) {
                if(strcmp(v.second.data().c_str(), "false") == 0) {
                    std::cout << "Adding peer failed" << std::endl;
                    return 0;
                } else {
                    std::cout << "Adding peer succeeded" << std::endl;
                    return 0;
                }
            }
        }

        return 0;
    }

    // --- Peers
    if (strcmp(argv[1], "peers") == 0) {
        response = client->get("/peers", ApiKey::getApiKey());
        if(response.empty()) {
            return 0;
        }

        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);

        std::string ip;
        std::string blockHeight;

        for (boost::property_tree::ptree::value_type &v : pt) {
            if (strcmp(v.first.data(), "peers") == 0) {
                for (boost::property_tree::ptree::value_type &v2 : v.second) {
                    for (boost::property_tree::ptree::value_type &v3 : v2.second) {
                        if (strcmp(v3.first.data(), "ip") == 0) {
                            ip = v3.second.data();
                        }

                        if (strcmp(v3.first.data(), "blockHeight") == 0) {
                            blockHeight = v3.second.data();
                        }
                    }
                    std::cout << ip << ", blockheight: " << blockHeight << std::endl;
                }
            }
        }

        return 0;
    }

    // --- reindex
    if (strcmp(argv[1], "reindex") == 0) {
        char clientInput;
        do {
            std::cout << "Are you sure to start the reindex? [y/n]" <<  std::endl;
            std::cin >> clientInput;
        } while( !std::cin.fail() && clientInput!='y' && clientInput!='n' );

        if(clientInput == 'n') {
            return 0;
        }

        std::cout << "starting reindexation..." <<  std::endl;

        response = client->get("/reindex/start", ApiKey::getApiKey());
        if(response.empty()) {
            return 0;
        }

        std::string isReindexing = "true";

        do {
            response = client->get("/reindex/status", ApiKey::getApiKey());
            if (response.empty()) {
                return 0;
            }

            std::stringstream ss(response);
            boost::property_tree::ptree pt;
            boost::property_tree::read_json(ss, pt);

            std::string reindexHeight;
            std::string currentBlockchainHeight;

            for (boost::property_tree::ptree::value_type &v : pt) {
                if (strcmp(v.first.data(), "reindexHeight") == 0) {
                    reindexHeight = v.second.data();
                }

                if (strcmp(v.first.data(), "currentBlockchainHeight") == 0) {
                    currentBlockchainHeight = v.second.data();
                }

                if (strcmp(v.first.data(), "isReindexing") == 0) {
                    isReindexing = v.second.data();
                }
            }

            std::cout << "[" << reindexHeight << "/" << currentBlockchainHeight <<  "] blocks reindexated" <<  std::endl;
            sleep(2);
        } while(isReindexing != "false");

        std::cout << "Done!" <<  std::endl;

        return 0;

    }

    // --- Balance
/*
    response = client->get("/wallet", ApiKey::getApiKey());
    std::cout << response << std::endl;
*/

    std::cout << "Missing parameter, options are: web, status, start-minting, stop-minting, add-peer, peers, reindex" << std::endl;

    return 0;
}
