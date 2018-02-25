
#ifndef TX_LOADER_H
#define TX_LOADER_H

class Loader {
public:
    static bool createTouchFilesAndDirectories();
    static bool isLocked();
    static bool loadConfig();
    static bool loadDelegates();
    static bool loadBestBlockHeaders();
    static bool loadCertStore();
    static bool loadPathSum();
    static bool loadWallet();
};


#endif //TX_LOADER_H
