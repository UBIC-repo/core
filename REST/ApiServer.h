

#ifndef TX_APISERVER_H
#define TX_APISERVER_H

#include <string>
#include <vector>

class ApiServer {
private:
    std::string route(std::vector<std::string> urlParts, std::string jsonPost);
public:
    void run();
};


#endif //TX_APISERVER_H
