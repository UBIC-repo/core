
#ifndef TX_FS_H
#define TX_FS_H

#include <vector>
#include "../streams.h"
#include "../Tools/Log.h"
#include "../ChainParams.h"

class FS {
public:
    static FS& Instance(){
        static FS instance;
        return instance;
    }

    static bool overwriteFile(std::vector<unsigned char> path, std::vector<unsigned char> content);
    static bool overwriteFile(std::vector<unsigned char> path, uint64_t startPosition, std::vector<unsigned char> content);

    template < class Serializable >
    static bool deserializeFromFile(std::vector<unsigned char> path, Serializable& data, uint64_t bufferSize) {
        uint64_t nextPos;
        bool eof;
        return deserializeFromFile(path, bufferSize, 0, data, nextPos, eof);
    }

    template < class Serializable >
    static bool deserializeFromFile(std::vector<unsigned char> path, uint64_t bufferSize, uint64_t pos, Serializable& data, uint64_t& nextPos, bool& eof) {
        char pData[512];
        memcpy(pData, (char*)path.data(), path.size());
        memcpy(pData + path.size(), "\0", 1);

        FILE *file = fopen(pData, "rb");
        CAutoFile filein(file, SER_DISK, SERIALIZATION_VERSION);
        //CBufferedFile filein(file, bufferSize, 0, SER_DISK, SERIALIZATION_VERSION);

        if (filein.IsNull() || filein.isEmpty()) {
            Log(LOG_LEVEL_ERROR) << "failed to open file " << pData;
            filein.fclose();
            return false;
        }

        filein.Seek(pos);
        filein >> data;

        nextPos = filein.GetPos();
        eof = filein.eof();
        filein.fclose();

        return true;
    }

    template < class Serializable >
    static bool serializeToFile(std::vector<unsigned char> path, Serializable& data) {
        FS::touchFile(path);

        char pData[512];
        memcpy(pData, (char*)path.data(), path.size());
        memcpy(pData + path.size(), "\0", 1);

        FILE *file = fopen(pData, "rb+");
        //CBufferedFile fileout(file, BLOCK_SIZE_MAX, BLOCK_SIZE_MAX, SER_DISK, SERIALIZATION_VERSION);

        CAutoFile fileout(file, SER_DISK, SERIALIZATION_VERSION);

        if (fileout.IsNull()) {
            Log(LOG_LEVEL_ERROR) << "failed to open file " << pData;
            fileout.fclose();
            return false;
        }

        fileout.jumpToEof();
        fileout << data;
        fileout.fclose();

        return true;
    }

    static bool touchFile(std::vector<unsigned char> path);
    static bool deleteFile(std::vector<unsigned char> path);
    static bool fileExists(std::vector<unsigned char> path);
    static uint64_t getEofPosition(std::vector<unsigned char> path);
    static std::vector<unsigned char> readFile(std::vector<unsigned char> path);
    static std::vector<unsigned char> readFile(std::vector<unsigned char> path, uint64_t startPosition, uint64_t size);
    static std::vector<std::vector<unsigned char> > readDir(std::vector<unsigned char> path);
    static bool isDir(std::vector<unsigned char> path);
    static bool createDirectory(std::vector<unsigned char> path);
    static std::vector<unsigned char> getBasePath();
    static std::vector<unsigned char> getLockPath();
    static std::vector<unsigned char> getWebBasePath();
    static std::vector<unsigned char> getX509DirectoryPath();
    static std::vector<unsigned char> getCertDirectoryPath();
    static std::vector<unsigned char> getImportDirectoryPath();
    static std::vector<unsigned char> getBlockDatDirectoryPath();
    static std::vector<unsigned char> getBlockDatPath();
    static std::vector<unsigned char> getBlockHeadersPath();
    static std::vector<unsigned char> getMyTransactionsPath();
    static std::vector<unsigned char> getVotesPath();
    static std::vector<unsigned char> getBestBlockHeadersPath();
    static std::vector<unsigned char> getWalletPath();
    static std::vector<unsigned char> getAddressStorePath();
    static std::vector<unsigned char> getBlockIndexStorePath();
    static std::vector<unsigned char> getNTPSKStorePath();
    static std::vector<unsigned char> getDSCCounterStorePath();
    static std::vector<unsigned char> getLogPath();
    static std::vector<unsigned char> getHome();
    static std::vector<unsigned char> getConfigBasePath();
    static std::vector<unsigned char> getConfigPath();
    static bool clearFile(std::vector<unsigned char> path);
    static std::vector<unsigned char> concatPaths(std::vector<unsigned char> path1, std::vector<unsigned char> path2);
    static std::vector<unsigned char> concatPaths(std::vector<unsigned char> path1, const char* path2);
    static std::vector<unsigned char> concatPaths(const char* path1, const char* path2);
    static void charPathFromVectorPath(char* pData, std::vector<unsigned char> vectorPath);
};


#endif //TX_FS_H
