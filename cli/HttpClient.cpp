
#include "HttpClient.h"
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/read.hpp>
#include <iomanip>

using namespace boost::asio;
using boost::asio::ip::tcp;

std::string HttpClient::url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
        std::string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

std::string HttpClient::get(std::string url, std::string apiKey) {
    try {
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", "12303");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "GET " << url << " HTTP/1.0\r\n";
        request_stream << "apiKey: " << apiKey << "\r\n";
        request_stream << "Host: 127.0.0.1\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        boost::asio::write(socket, request);
        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        // Check that response is OK.
        std::istream response_stream(&response);
        std::string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        std::string status_message;
        std::getline(response_stream, status_message);
        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            std::cout << "Invalid response\n";
            return "";
        }
        if (status_code != 200)
        {
            std::cout << "Response returned with error code " << status_code << "\n";
            return "";
        }

        // Read the response headers, which are terminated by a blank line.
        boost::asio::read_until(socket, response, "\r\n\r\n");

        // Process the response headers.
        std::string header;
        while (std::getline(response_stream, header) && header != "\r") {
            //std::cout << header << "\n";
        }
        //std::cout << "\n";
        //std::cout << "-------------------------\n";

        std::ostringstream ss;

        // Write whatever content we already have to output.
        //if (response.size() > 0)
        ss << &response;


        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        while (boost::asio::read(socket, response,
                boost::asio::transfer_at_least(1), error))
            ss << &response;

        if (error != boost::asio::error::eof)
            throw boost::system::system_error(error);

        return ss.str();
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << ", verify that ubicd is running or try /etc/init.d/ubic restart\n";
    }
    return "";
}

std::string HttpClient::post(std::string url, std::string apiKey, std::string post) {
    try {
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", "12303");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "POST " << url << " HTTP/1.0\r\n";
        request_stream << "apiKey: " << apiKey << "\r\n";
        request_stream << "Host: 127.0.0.1\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: keep-alive\r\n\r\n";
        request_stream << "json=" << post;

        boost::asio::write(socket, request);
        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        // Check that response is OK.
        std::istream response_stream(&response);
        std::string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        std::string status_message;
        std::getline(response_stream, status_message);
        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            std::cout << "Invalid response\n";
            return "";
        }
        if (status_code != 200)
        {
            std::cout << "Response returned with error code " << status_code << "\n";
            return "";
        }

        // Read the response headers, which are terminated by a blank line.
        boost::asio::read_until(socket, response, "\r\n\r\n");

        // Process the response headers.
        std::string header;
        while (std::getline(response_stream, header) && header != "\r") {
            //std::cout << header << "\n";
        }
        //std::cout << "\n";
        //std::cout << "-------------------------\n";

        std::ostringstream ss;

        // Write whatever content we already have to output.
        //if (response.size() > 0)
        ss << &response;


        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        while (boost::asio::read(socket, response,
                                 boost::asio::transfer_at_least(1), error))
            ss << &response;

        if (error != boost::asio::error::eof)
            throw boost::system::system_error(error);

        return ss.str();
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << "\n";
    }
    return "";
}
