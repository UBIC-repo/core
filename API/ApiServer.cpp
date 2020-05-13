#include "ApiServer.h"
#include "../Tools/Log.h"
#include "Api.h"
#include "../Config.h"
#include "../Scripts/UScript.h"
#include "../Scripts/AddCertificateScript.h"
#include "../App.h"
#include <boost/asio.hpp>
#include <regex>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

using boost::asio::ip::tcp;
using boost::property_tree::ptree;

std::vector<std::string> getUrlParts(const std::string request) {
    std::vector<std::string> urlParts;

    std::regex rgx(".* (.*) .*");
    std::smatch match;

    if (std::regex_search(request.begin(), request.end(), match, rgx)) {
        const std::string s = match[1];
        boost::split(urlParts, s, boost::is_any_of("/"));
    }

    for(std::vector<std::string>::iterator it = urlParts.begin(); it != urlParts.end();) {
        if(it->size() == 0) {
            it = urlParts.erase(it);
        } else {
            it++;
        }
    }

    return urlParts;
}

std::string urlDecode(std::string str){
    std::string ret;
    char ch;
    int i, ii, len = str.length();

    for (i=0; i < len; i++){
        if(str[i] != '%'){
            if(str[i] == '+')
                ret += ' ';
            else
                ret += str[i];
        }else{
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

std::string getJsonPost(const std::string request) {
    std::cout << "json request: " << request << '\n';
    std::regex rgx(".*json=(.*)$");
    std::smatch match;

    if (std::regex_search(request.begin(), request.end(), match, rgx)) {
        std::cout << "json match: " << urlDecode(match[1]) << '\n';
        return urlDecode(match[1]);
    }

    return "";
}

std::string getApiKey(const std::string request) {
    std::regex rgx("apiKey:[    ]*(.*)\r\n");
    std::smatch match;

    if (std::regex_search(request.begin(), request.end(), match, rgx)) {
        return urlDecode(match[1]);
    }

    return "";
}

std::string ApiServer::route(std::vector<std::string> urlParts, std::string jsonPost) {

    App& app = App::Instance();

    if(app.isStarting()) {
        return "{\"success\": false, \"status\": \"starting\"}";
    }

    if(urlParts.size() >= 1) {
        if(urlParts.at(0) == "certificates") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1) == "root") {
                    if(urlParts.size() >= 3) {

                    } else {
                        return Api::getRootCertificates();
                    }
                }
                if(urlParts.at(1) == "csca") {
                    if(urlParts.size() == 3) {
                        if(urlParts.at(2) == "add") {
                            return Api::addCert(jsonPost, TYPE_CSCA);
                        } else if(urlParts.at(2) == "remove") {
                            return Api::removeCert(jsonPost, TYPE_CSCA);
                        } else {
                            return Api::getCSCACertificate(urlParts.at(2));
                        }
                    } else {
                        return Api::getCSCACertificates();
                    }
                }
                if(urlParts.at(1) == "dsc") {
                    if(urlParts.size() == 3) {
                        if(urlParts.at(2) == "add") {
                            return Api::addCert(jsonPost, TYPE_DSC);
                        } else if(urlParts.at(2) == "remove") {
                            return Api::removeCert(jsonPost, TYPE_DSC);
                        } else {
                            return Api::getDSCCertificate(urlParts.at(2));
                        }
                    } else {
                        return Api::getDSCCertificates();
                    }
                }
            } else {

            }
        } else if(urlParts.at(0) == "blocks") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1).size() == 64) {
                    return Api::getBlock(Hexdump::hexStringToVector(urlParts.at(1)));
                } else {
                    return Api::getBlock((uint32_t)atoi(urlParts.at(1).c_str()));
                }
            }
        } else if(urlParts.at(0) == "ubi") {
            if(urlParts.size() == 2) {
                if(urlParts.at(1) == "register-passport") {
                    return Api::readPassport(jsonPost);
                }

                if(urlParts.at(1) == "do-kyc") {
                    return Api::doKYC(jsonPost);
                }

                if(urlParts.at(1) == "verify-kyc") {
                    return Api::verifyKYC(jsonPost);
                }
            }
            return Api::getUbi();
        } else if(urlParts.at(0) == "fees") {
            return Api::getFees();
        } else if(urlParts.at(0) == "txpool") {
            return Api::getTxPool();
        } else if(urlParts.at(0) == "incoming") {
            return Api::getIncomingTx();
        } else if(urlParts.at(0) == "reindex") {
            if(urlParts.size() == 2) {
                if (urlParts.at(1) == "start") {
                    return Api::reindex();
                }

                if (urlParts.at(1) == "status") {
                    return Api::reindexStatus();
                }
            }
        } else if(urlParts.at(0) == "delegates") {
            if(urlParts.size() == 1) {
                return Api::getDelegates();
            } else {
                if(urlParts.size() == 2) {
                    if(urlParts.at(1) == "vote") {
                        return Api::vote(jsonPost);
                    } else if(urlParts.at(1) == "unvote") {
                        return Api::unvote(jsonPost);
                    }
                }
            }
        } else if(urlParts.at(0) == "wallet") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1) == "pay") {
                    return Api::pay(jsonPost);
                } else if(urlParts.at(1) == "transactions")  {
                    return Api::myTransactions();
                } else if(urlParts.at(1) == "createTransaction") {
                    return Api::createTransaction(jsonPost);
                } else if(urlParts.at(1) == "send") {
                    return Api::sendTransaction(jsonPost);
                } else if(urlParts.at(1) == "generate-key-pair") {
                    return Api::generateKeyPair();
                } else if(urlParts.at(1) == "create-transaction-with-private-key") {
                    return Api::createTransactionWithPrivateKey(jsonPost);
                }
            }
            return Api::getWallet();
        } else if(urlParts.at(0) == "mint") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1) == "start") {
                    return Api::startMint();
                } else if(urlParts.at(1) == "stop") {
                    return Api::stopMint();
                } else if(urlParts.at(1) == "status") {
                    return Api::mintStatus();
                }
            }
        } else if(urlParts.at(0) == "peers") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1) == "add") {
                    return Api::addPeer(jsonPost);
                } else if(urlParts.at(1) == "remove") {
                    return Api::removePeer(jsonPost);
                }
            }
            return Api::getPeers();
        } else if(urlParts.at(0) == "bans") {
            if(urlParts.size() >= 2) {
                if(urlParts.at(1) == "add") {
                    return Api::addBan(jsonPost);
                } else if(urlParts.at(1) == "remove") {
                    return Api::removeBan(jsonPost);
                }
            }
            return Api::getBans();
        } else if(urlParts.at(0) == "address") {
            if(urlParts.size() == 2) {
                return Api::getAddress(urlParts.at(1));
            }
        } else if(urlParts.at(0) == "currencies") {
            if(urlParts.size() == 1) {
                return Api::getCurrencies();
            }
        }
    }
    return Api::getIndex();
}

void ApiServer::run() {

    try
    {
        Config& config = Config::Instance();
        boost::asio::io_service io_service;
        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), NET_API_PORT));

        for (;;) {
            tcp::socket socket(io_service);
            acceptor.accept(socket);
	        boost::system::error_code ec;

            char *buffer = (char *) malloc(65048 * 2 * sizeof(char));

            try {
                std::size_t bufferSize = socket.read_some(boost::asio::buffer(buffer, 65048), ec);

#if defined(_WIN32)
                Sleep(1);
#else
                usleep(200);
#endif

                while(socket.available() > 0) {
                    bufferSize += socket.read_some(boost::asio::buffer(buffer + bufferSize, 65048 - bufferSize), ec);
                    #if defined(_WIN32)
                                        Sleep(1);
                    #else
                                        usleep(200);
                    #endif
                }

                Log(LOG_LEVEL_INFO) << "socket.available():" << (uint64_t)socket.available();

                if (!config.getAllowFrom().empty() &&
                    config.getAllowFrom() != socket.remote_endpoint().address().to_string()) {
                    Log(LOG_LEVEL_WARNING) << "Unallowed API request from IP:"
                                           << socket.remote_endpoint().address().to_string();
                    socket.close();
                    free(buffer);
                    continue;
                }

                const std::string bufferStr(buffer, bufferSize);
                Log(LOG_LEVEL_INFO) << "bufferStr:" << bufferStr;

                std::regex rgx("Expect:[    ]100*(.*)\r\n");
                std::smatch match;

                if (std::regex_search(bufferStr.begin(), bufferStr.end(), match, rgx)) { // Expect: 100-continue
                    char *responseBuffer = (char *) malloc(1024 * sizeof(char));

                    std::string response = "HTTP/1.0 100 Continue\r\n";
                    memcpy(responseBuffer, response.c_str(), response.size());

                    boost::system::error_code ignored_error;
                    boost::asio::write(socket, boost::asio::buffer(responseBuffer,  response.size()), ignored_error);
                }

                //Log(LOG_LEVEL_INFO) << "API Incoming:" << bufferStr;
                std::vector<std::string> urlParts = getUrlParts(bufferStr);


                //std::string header = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n";
                std::string header = "HTTP/1.0 200 OK\r\nAccess-Control-Allow-Origin: http://";
                header.append(config.getAllowFrom());
                header.append(":6789\r\nContent-Type: application/json; charset=utf-8\r\n");
                header.append("Access-Control-Allow-Headers: apiKey\r\n\r\n");

                std::string response;

                if (config.getApiKey().compare(getApiKey(bufferStr)) == 0) {
                    std::string jsonPost = getJsonPost(bufferStr);
                    response = route(urlParts, jsonPost);
                    response = header.append(response);
                } else {
                    response = "{\"error\":true, \"message\":\"wrong api key\"}";
                    response = header.append(response);
                }

                //Log(LOG_LEVEL_INFO) << "full api response: " << response;

                int len = response.size();

                int cursor = 0;
                while (cursor < len) {

                    char *responseBuffer = (char *) malloc(1024 * sizeof(char));
                    int copySize = 1024;

                    if (copySize > len - cursor) {
                        copySize = len - cursor;
                    }

                    memcpy(responseBuffer, response.c_str() + cursor, copySize);

                    boost::system::error_code ignored_error;
                    boost::asio::write(socket, boost::asio::buffer(responseBuffer, copySize), ignored_error);
                    cursor += 1024;
                    free(responseBuffer);
                }
                socket.close();
                free(buffer);
            } catch (const std::exception &e) {
                try {
                    socket.close();
                    free(buffer);
                } catch (const std::exception &e) {
                    Log(LOG_LEVEL_WARNING) << "API server exception3:" << e.what();
                }
                Log(LOG_LEVEL_WARNING) << "API server exception2:" << e.what();
            }
        }
    }
        catch (std::exception& e)
    {
        Log(LOG_LEVEL_WARNING) << "API server exception1:" << e.what();
    }
}
