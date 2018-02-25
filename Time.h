
#ifndef TX_TIME_H
#define TX_TIME_H


#include <cstdint>
#include <chrono>

class Time {
public:
    static uint64_t getCurrentMicroTimestamp() {
        std::chrono::microseconds us = std::chrono::duration_cast< std::chrono::microseconds >(
                std::chrono::system_clock::now().time_since_epoch()
        );
        return (uint64_t)us.count();
    }

    static uint64_t getCurrentTimestamp() {
        std::chrono::seconds us = std::chrono::duration_cast< std::chrono::seconds >(
                std::chrono::system_clock::now().time_since_epoch()
        );
        return (uint64_t)us.count();
    }
};


#endif //TX_TIME_H
