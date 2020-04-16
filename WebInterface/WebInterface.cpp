
#include <boost/asio/io_service.hpp>
#include <boost/asio/buffer.hpp>
#include <iostream>
#include <boost/asio/write.hpp>
#include "WebInterface.h"
#include "../Tools/Log.h"
#include "../FS/FS.h"
#include "../Config.h"
#include <boost/asio.hpp>
#include <thread>
#include <regex>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#if defined(_WIN32)
#include <shellapi.h>
#endif

using boost::asio::ip::tcp;

std::string getUrlPath(const std::string request) {
    std::vector<std::string> urlParts;

    std::regex rgx(".* (.*) .*");
    std::smatch match;

    if (std::regex_search(request.begin(), request.end(), match, rgx)) {
        std::cout << "url match: " << match[1] << '\n';
        return match[1];
    }

    return "";
}

// make sure it is not possible to read another file
bool isInWhiteList(std::string path) {
    std::vector<std::string> whiteList;
    whiteList.emplace_back("/ubi.html");
    whiteList.emplace_back("/jquery-3.2.1.js");
    whiteList.emplace_back("/bootstrap-3.3.7-dist/js/bootstrap.min.js");
    whiteList.emplace_back("/validator.js");
    whiteList.emplace_back("/bootstrap-datepicker.min.js");
    whiteList.emplace_back("/nprogress-master/nprogress.js");
    whiteList.emplace_back("/bootstrap-3.3.7-dist/css/bootstrap.min.css");
    whiteList.emplace_back("/nprogress-master/nprogress.css");
    whiteList.emplace_back("/bootstrap-datepicker3.min.css");
    whiteList.emplace_back("/bootstrap-3.3.7-dist/fonts/glyphicons-halflings-regular.woff2");
    whiteList.emplace_back("/bootstrap-3.3.7-dist/fonts/glyphicons-halflings-regular.woff");
    whiteList.emplace_back("/bootstrap-3.3.7-dist/fonts/glyphicons-halflings-regular.ttf");
    whiteList.emplace_back("/jquery.bootstrap-growl.min.js");

    return std::find(whiteList.begin(), whiteList.end(), path) != whiteList.end();
}

std::string readFile(std::string urlPath) {
    std::vector<unsigned char> absolutePath = FS::concatPaths(FS::getWebBasePath(), urlPath.data());
    std::vector<unsigned char> vFileContent = FS::readFile(absolutePath);

    Log(LOG_LEVEL_INFO) << "readfile: " << absolutePath.data();

    char *cFileContent = (char*)malloc(750000);
    memcpy(cFileContent, (char*)vFileContent.data(), vFileContent.size());
    memcpy(cFileContent + vFileContent.size(), "\0", 1);

    std::string sFileContent(cFileContent, vFileContent.size());
    free(cFileContent);

    return sFileContent;
}

void WebInterface::run() {
    try
    {
        boost::asio::io_service io_service;
        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), NET_WEB_PORT));
        Config& config = Config::Instance();

#if defined(_WIN32)
        char* url = (char*)malloc(sizeof(char) * 128);
        std::string host = "http://127.0.0.1:6789/#";
        std::memcpy(url, host.c_str(), host.length());
        std::memcpy(url + host.length(), config.getApiKey().c_str(), config.getApiKey().length());
        std::memcpy(url + host.length() + config.getApiKey().length(), "\0", 1);
        Log(LOG_LEVEL_INFO) << "URl:" << url;
        ShellExecute(0, 0, url, 0, 0 , SW_SHOW );
#endif

        for (;;)
        {
            tcp::socket socket(io_service);
            acceptor.accept(socket);
	    boost::system::error_code ec;

            char* buffer = (char*)malloc(65048 * sizeof(char));
            std::size_t bufferSize = socket.read_some(boost::asio::buffer(buffer, 65048), ec);
            if(socket.available() > 0) {
                bufferSize += socket.read_some(boost::asio::buffer(buffer + bufferSize, 65048 - bufferSize), ec);
            }

#if defined(_WIN32)
            Sleep(1);
#else
            usleep(200);
#endif
            //std::cout << "available:" << socket.available() << std::endl;

            if(!config.getAllowFrom().empty() && config.getAllowFrom() != socket.remote_endpoint().address().to_string()) {
                Log(LOG_LEVEL_WARNING) << "Unallowed API request from IP:" << socket.remote_endpoint().address().to_string();
                socket.close();
                free(buffer);
                continue;
            }

            std::string bufferStr(buffer, bufferSize);
            std::cout << "Incoming:" << bufferStr << std::endl;
            std::cout << "Incoming2:" << buffer << std::endl;
            std::string urlPath = getUrlPath(bufferStr);

            if(urlPath == "/") {
                urlPath = "/ubi.html";
            }

            //std::string header = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n";
            std::string header = "HTTP/1.0 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
            std::string response = "";

            if(isInWhiteList(urlPath)) {
                response = readFile(urlPath);
                response = header.append(response);
            } else {
                response = "HTTP/1.0 403 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
            }

            //Log(LOG_LEVEL_INFO) << "full api response: " << response;

            int len = response.size();

            int cursor = 0;
            while(cursor < len) {

                char responseBuffer[1024];
                int copySize = 1024;

                if(copySize > len - cursor) {
                    copySize = len - cursor;
                }

                memcpy(responseBuffer, response.c_str() + cursor, copySize);

                boost::system::error_code ignored_error;
                boost::asio::write(socket, boost::asio::buffer(responseBuffer, copySize), ignored_error);
                cursor += 1024;
            }
            socket.close();
            free(buffer);
        }
    }
    catch (std::exception& e)
    {
        Log(LOG_LEVEL_WARNING) << "Webinterface exception:" << e.what();
    }
}
