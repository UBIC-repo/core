
#ifndef TX_LOG_H
#define TX_LOG_H

#define LOG_LEVEL_INFO 0x00
#define LOG_LEVEL_NOTICE 0x01
#define LOG_LEVEL_WARNING 0x02
#define LOG_LEVEL_ERROR 0x03
#define LOG_LEVEL_CRITICAL_ERROR 0x04

#include <thread>
#include <iostream>
#include <fstream>
#include <mutex>
#include "Hexdump.h"
#include "../UAmount.h"
#include "../Serialization/streams.h"


class Log {
private:
    uint8_t logLevel = 0x00;
public:
    static std::mutex logLock;
    std::ostream* currentStream;
    std::filebuf fb;

    Log() {
        logLock.lock();
    }

    Log(uint8_t level);

    Log& operator<<(CDataStream obj);
    Log& operator<<(std::vector<unsigned char> obj);
    Log& operator<<(const char* obj);
    Log& operator<<(const unsigned char* obj);
    Log& operator<<(std::string obj);
    Log& operator<<(uint32_t obj);
    Log& operator<<(uint64_t obj);
    Log& operator<<(float obj);
    Log& operator<<(int obj);
    Log& operator<<(bool obj);
    Log& operator<<(UAmount obj);
    Log& operator<<(UAmount32 obj);
    ~Log();

};


#endif //TX_LOG_H
