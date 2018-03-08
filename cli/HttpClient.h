
#ifndef UBIC_TOOL_HTTPCLIENT_H
#define UBIC_TOOL_HTTPCLIENT_H

#include <string>

class HttpClient {
public:
    std::string get(std::string url, std::string apiKey);
    //std::string post();
};


#endif //UBIC_TOOL_HTTPCLIENT_H
