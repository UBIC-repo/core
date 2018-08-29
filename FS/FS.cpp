
#include "FS.h"
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <fcntl.h>
#include <regex>
#include <boost/algorithm/string/split.hpp>

bool FS::overwriteFile(std::vector<unsigned char> path, std::vector<unsigned char> content) {
    return FS::overwriteFile(path, 0, content);
}

bool FS::overwriteFile(std::vector<unsigned char> path, uint64_t startPosition, std::vector<unsigned char> content) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    std::fstream fout(cPath, std::fstream::in | std::fstream::out | std::fstream::binary );
    fout.seekp( startPosition );
    fout.write( (char*)content.data() , content.size() );
    fout.close();
    return true;
}

uint64_t FS::getEofPosition(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    FILE *src = fopen(cPath, "rb");
    if(src == NULL) {
        return (uint64_t)0;
    }
    fseek(src, 0, SEEK_END);
    uint64_t eof = (uint64_t) ftell(src);
    fclose(src);
    return eof;
}

bool FS::touchFile(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
#if defined(_WIN32)
    int fd = open(cPath, O_WRONLY|O_CREAT, 0666);
#else
    int fd = open(cPath, O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666);
#endif

    if(fd < 0)
    {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

bool FS::deleteFile(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    return !std::remove(cPath);
}

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

std::vector<unsigned char> FS::readFile(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    FILE *file = fopen(cPath, "rb");
    if(file == nullptr) {
        return std::vector<unsigned char>();
    }
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* pch = (char*)malloc(sizeof(char) * size);
    fread(pch, 1, (size_t)size, file);
    fclose(file);

    return std::vector<unsigned char>(pch, pch + size);
}

std::vector<unsigned char> FS::readFile(std::vector<unsigned char> path, uint64_t startPosition, uint64_t size) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    FILE *file = fopen(cPath, "rb");
    if(file == nullptr) {
        return std::vector<unsigned char>();
    }
    fseek(file, startPosition, SEEK_SET);

    char* pch = (char*)malloc(sizeof(char) * size);
    fread(pch, 1, size, file);
    fclose(file);

    auto fVector = std::vector<unsigned char>(pch, pch + size);
    free(pch);

    return fVector;
}

std::vector<std::vector<unsigned char> > FS::readDir(std::vector<unsigned char> path) {
    std::vector<std::vector<unsigned char> > rval;

    char pData[512];
    memcpy(pData, (char*)path.data(), path.size());
    memcpy(pData + path.size(), "\0", 1);

    const boost::filesystem::path p(pData);
    for(auto& entry : boost::make_iterator_range(boost::filesystem::directory_iterator(p), {})) {

        size_t pathLength = entry.path().string().length();
        char* cPath = (char*)malloc(sizeof(char) * (pathLength + 1));
        std::strcpy(cPath, entry.path().string().c_str());
        std::vector<unsigned char> dPath(cPath, cPath + pathLength);
        rval.emplace_back(dPath);
    }

    return rval;
}

bool FS::isDir(std::vector<unsigned char> path) {
    const boost::filesystem::path p((char*)path.data());
    return boost::filesystem::is_directory(p);
}

bool FS::createDirectory(std::vector<unsigned char> path) {
    char pData[512];
    FS::charPathFromVectorPath(pData, path);
    return boost::filesystem::create_directory(pData);
}

std::vector<unsigned char> FS::getBasePath() {
    const char *t = BASE_PATH;
    return std::vector<unsigned char>(t, t + strlen(t));
}

std::vector<unsigned char> FS::getLockPath() {
    return FS::concatPaths(FS::getBasePath(), ".lock");
}

std::vector<unsigned char> FS::getWebBasePath() {
    const char *t = BASE_WEB_PATH;
    return std::vector<unsigned char>(t, t + strlen(t));
}

std::vector<unsigned char> FS::getX509DirectoryPath() {
    return FS::concatPaths(FS::getBasePath(), "x509/");
}

std::vector<unsigned char> FS::getCertDirectoryPath() {
    return FS::concatPaths(FS::getBasePath(), "certs/");
}

std::vector<unsigned char> FS::getImportDirectoryPath() {
    return FS::concatPaths(FS::getBasePath(), "import/");
}

std::vector<unsigned char> FS::getBlockDatDirectoryPath() {
    return FS::concatPaths(FS::getBasePath(), "blockdat/");
}

std::vector<unsigned char> FS::getBlockDatPath() {

    std::vector<std::vector<unsigned char> > fileList = FS::readDir(FS::getBlockDatDirectoryPath());

    uint32_t currentBlkFileNbrI = 0;
    std::vector<unsigned char> currentBlkFile = FS::concatPaths(FS::getBlockDatDirectoryPath(), "00000000.dat");
    for(std::vector<unsigned char> file : fileList) {

        const std::string fileString((char*)file.data(), file.size());

        std::regex rgx(".*/(0.*).dat$");
        std::smatch match;

        if (std::regex_search(fileString.begin(), fileString.end(), match, rgx)) {
            if(atoi(match[1].str().data()) > currentBlkFileNbrI) {
                currentBlkFile = file;
                currentBlkFileNbrI = atoi(match[1].str().data());
            }
        }
    }

    if(FS::getEofPosition(currentBlkFile) > BLOCK_FILES_MAX_SIZE) {

        std::string currentBlkFileNbrS2;

        char* currentBlkFileNbrS = (char*)malloc(sizeof(char) * 32);
        sprintf(currentBlkFileNbrS, "%d", currentBlkFileNbrI + 1);
        char* prefix = (char*)malloc(sizeof(char) * 32);
        sprintf(prefix, "0");

        int currentBlkFileNbrSLength  = (int) strlen(currentBlkFileNbrS);

        for(int i  = currentBlkFileNbrSLength; i < 8 - 1; i++) {
            sprintf(prefix, "0%s", prefix);
            //Log(LOG_LEVEL_INFO) << "prefix: " << prefix;
        }

        strcat(prefix, currentBlkFileNbrS);
        //Log(LOG_LEVEL_INFO) << "prefix: " << prefix;

        std::vector<unsigned char> nPath = FS::concatPaths(FS::getBlockDatDirectoryPath(), prefix);
        nPath = FS::concatPaths(nPath, ".dat");
        FS::touchFile(nPath);


        Log(LOG_LEVEL_INFO) << "new BlkFile: " << nPath.data();
        return nPath;
    }

    return currentBlkFile;
}

std::vector<unsigned char> FS::getBlockHeadersPath() {
    return FS::concatPaths(FS::getBasePath(), "headers.mdb");
}

std::vector<unsigned char> FS::getMyTransactionsPath() {
    return FS::concatPaths(FS::getBasePath(), "myTransactions.mdb");
}

std::vector<unsigned char> FS::getVotesPath() {
    return FS::concatPaths(FS::getBasePath(), "votes.mdb");
}

std::vector<unsigned char> FS::getBestBlockHeadersPath() {
    return FS::concatPaths(FS::getBasePath(), "bestHeaders.dat");
}

std::vector<unsigned char> FS::getWalletPath() {
    return FS::concatPaths(FS::getConfigBasePath(), "wallet.dat");
}

std::vector<unsigned char> FS::getAddressStorePath() {
    return FS::concatPaths(FS::getBasePath(), "AddressStore.mdb");
}

std::vector<unsigned char> FS::getBlockIndexStorePath() {
    return FS::concatPaths(FS::getBasePath(), "BlockIndexStore.mdb");
}

std::vector<unsigned char> FS::getNTPSKStorePath() {
    return FS::concatPaths(FS::getBasePath(), "NTPSKStore.mdb");
}

std::vector<unsigned char> FS::getDSCCounterStorePath() {
    return FS::concatPaths(FS::getBasePath(), "DSCCounterStore.mdb");
}

std::vector<unsigned char> FS::getLogPath() {
    return FS::concatPaths(FS::getBasePath(), "LOGS/");
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
        Log(LOG_LEVEL_ERROR) << "Couldn't get home path";
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

bool FS::clearFile(std::vector<unsigned char> path) {
    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);
    FILE *file = fopen(cPath, "wb+");
    fclose(file);

    return true;
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
