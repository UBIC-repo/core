
#ifndef TX_APP_H
#define TX_APP_H


#include "FS/FS.h"

#if defined(_WIN32)
#include <synchapi.h>
#else
#include <unistd.h>
#endif

class App {
private:
    bool terminateSignal = false;
    bool reindexing = false;
    bool starting = false;
    uint32_t reindexingHeight = 0;
public:
    static App& Instance(){
        static App instance;
        return instance;
    }

    //@TODO use!
    void terminate() {
        terminateSignal = true;
#if defined(_WIN32)
        Sleep(3000);
#else
        sleep(3);
#endif
        immediateTerminate();
    }

    void immediateTerminate() {

        terminateSignal = true;
        if(FS::fileExists(FS::getLockPath())) {
            FS::deleteFile(FS::getLockPath());
        }
        std::exit(0);
    }

    bool getTerminateSignal() {
        return this->terminateSignal;
    }

    bool isReindexing() {
        return this->reindexing;
    }

    bool setReindexing(bool value) {
        this->reindexing = value;
    }

    uint32_t getReindexingHeight() {
        return reindexingHeight;
    }

    void setReindexingHeight(uint32_t reindexingHeight) {
        this->reindexingHeight = reindexingHeight;
    }

    bool isStarting() {
        return this->starting;
    }

    void setIsStarting(bool isStarting) {
        this->starting = isStarting;
    }
};


#endif //TX_APP_H
