
#include "FS.h"
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <fcntl.h>
#include <regex>
#include <boost/algorithm/string/split.hpp>
#include <iostream>


bool FS::fileExists(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    if (FILE *file = fopen(cPath, "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}

std::vector<unsigned char> FS::getBasePath() {
    const char *t = BASE_PATH;
    return std::vector<unsigned char>(t, t + strlen(t));
}

std::vector<unsigned char> FS::getHome() {
    char* home = nullptr;
#if defined(__linux__) || defined(__APPLE__)
    home = std::getenv("HOME");
    return FS::concatPaths(std::vector<unsigned char>(home, home + strlen(home)), "/");
#endif
#if defined(_WIN32)
    home = std::getenv("homepath");
    return FS::concatPaths(std::vector<unsigned char>(home, home + strlen(home)), "/");
#endif

    if(home == nullptr) {
        std::cout << "Couldn't get home path";
    }

    return std::vector<unsigned char>(home, home + strlen(home));
}

std::vector<unsigned char> FS::getConfigBasePath() {
    return FS::concatPaths(FS::getHome(), CONFIG_BASE_PATH);
}

std::vector<unsigned char> FS::getConfigPath() {
    const char* path = CONFIG_PATH;
    return FS::concatPaths(FS::getConfigBasePath(), path);
}


std::vector<unsigned char> FS::concatPaths(std::vector<unsigned char> path1, std::vector<unsigned char> path2) {
    path1.insert(path1.end(), path2.begin(), path2.end());
    return path1;
}

std::vector<unsigned char> FS::concatPaths(std::vector<unsigned char> path1, const char* path2) {
    std::vector<unsigned char> np(path2, path2 + strlen(path2));
    path1.insert(path1.end(), np.begin(), np.end());
    return path1;
}

std::vector<unsigned char> FS::concatPaths(const char* path1, const char* path2) {
    std::vector<unsigned char> bp(path1, path1 + strlen(path1));
    std::vector<unsigned char> np(path2, path2 + strlen(path2));

    return FS::concatPaths(bp, np);
}

void FS::charPathFromVectorPath(char* pData, std::vector<unsigned char> vectorPath) {
    memcpy(pData, (char*)vectorPath.data(), vectorPath.size());
    memcpy(pData + vectorPath.size(), "\0", 1);
}
