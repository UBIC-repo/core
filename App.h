
#ifndef TX_APP_H
#define TX_APP_H

#if defined(_WIN32)
#include <synchapi.h>
#else
#include <unistd.h>
#endif

class App {
private:
    bool terminateSignal = false;
    bool reindexing = false;
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
};


#endif //TX_APP_H
