
#ifndef TX_FS_H
#define TX_FS_H

#include <vector>

#define BASE_PATH "/var/ubic/"
#define CONFIG_BASE_PATH "ubic/"
#define CONFIG_PATH "config.ini"

class FS {
public:
    static bool fileExists(std::vector<unsigned char> path);
    static std::vector<unsigned char> getBasePath();
    static std::vector<unsigned char> getHome();
    static std::vector<unsigned char> getConfigBasePath();
    static std::vector<unsigned char> getConfigPath();
    static std::vector<unsigned char> concatPaths(std::vector<unsigned char> path1, std::vector<unsigned char> path2);
    static std::vector<unsigned char> concatPaths(std::vector<unsigned char> path1, const char* path2);
    static std::vector<unsigned char> concatPaths(const char* path1, const char* path2);
    static void charPathFromVectorPath(char* pData, std::vector<unsigned char> vectorPath);
};


#endif //TX_FS_H
