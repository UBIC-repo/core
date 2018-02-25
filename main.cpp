#include <iostream>
#include <boost/asio/io_service.hpp>
#include <thread>
#include "Transaction/Transaction.h"
#include "Wallet.h"
#include "CertStore/Cert.h"
#include "CertStore/CertStore.h"
#include "Tools/Log.h"
#include "BlockCreator/Mint.h"
#include "Loader.h"
#include "TxPool.h"
#include "REST/ApiServer.h"
#include "Network/Server.h"
#include "Consensus/VoteStore.h"
#include "Test/Test.h"
#include "WebInterface/WebInterface.h"
#include "Config.h"
#include "App.h"

void startMinting() {
    Mint& mint = Mint::Instance();
    mint.stopMinting();
    mint.startMintingService();
}

void startServer() {
    Log(LOG_LEVEL_INFO) << "Start Server";
    try
    {
        boost::asio::io_service io_service;

        tcp::endpoint endpoint(tcp::v4(), NET_PORT_INT);
        Server &server = Server::Instance(io_service, endpoint);

        io_service.run();
    }
    catch (std::exception& e)
    {
        Log(LOG_LEVEL_ERROR) << "Server Exception: " << e.what();
    }
}

void startApiServer() {
    ApiServer* apiServer = new ApiServer();
    apiServer->run();
}

void startWebInterface() {
    WebInterface* webInterface = new WebInterface();
    webInterface->run();
}

#if defined(__linux__)
void signalHandler(int signal) {
    Log(LOG_LEVEL_INFO) << "received shutdown signal";
    App& app = App::Instance();
    app.terminate();
}
#endif

#if defined(_WIN32)
BOOL WINAPI signalHandler(DWORD signal) {
    if (signal == CTRL_CLOSE_EVENT || signal == CTRL_LOGOFF_EVENT || signal == CTRL_SHUTDOWN_EVENT || signal == CTRL_C_EVENT) {
        Log(LOG_LEVEL_INFO) << "received shutdown signal";
        App& app = App::Instance();
        app.terminate();
    }
}
#endif

int main() {

    Log(LOG_LEVEL_INFO) << "Starting UBIC version " << VERSION;

    if(Loader::isLocked()) {
        Log(LOG_LEVEL_CRITICAL_ERROR) << "Found lock file "
                                      << FS::getLockPath()
                                      << " this means that either another instance of UBIC is running or that it wasn't shutdown properly";

        return 0;
    }



#if defined(__linux__)

    //daemonize
    pid_t pid;
    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGKILL, signalHandler);
    signal(SIGQUIT, signalHandler);

    pid = getpid();
    Log(LOG_LEVEL_INFO) << "Process ID:" << pid;

    FS::touchFile(Hexdump::stringToCharVector("/var/ubic/ubic.pid"));
    std::fstream fout("/var/ubic/ubic.pid", std::fstream::in | std::fstream::out | std::fstream::binary );
    fout.seekp( 0 );

    std::ostringstream oss;
    oss << pid;
    fout.write(oss.str().c_str(), oss.str().size());
    fout.close();


    fclose(stdout);
    fclose(stderr);

#endif
#if defined(_WIN32)
    SetConsoleCtrlHandler(signalHandler, TRUE);
#endif

    // @TODO add a lock
    //Loader::lock();
    Loader::createTouchFilesAndDirectories();
    Loader::loadConfig();
    Loader::loadDelegates();
    Loader::loadBestBlockHeaders();
    Loader::loadCertStore();
    Loader::loadPathSum();
    Loader::loadWallet();

    Mint& mint = Mint::Instance();
    TxPool& txPool = TxPool::Instance();
    Wallet& wallet = Wallet::Instance();

    Log(LOG_LEVEL_INFO) << "Final balance : " << wallet.getBalance();

    std::thread t1(&startApiServer);
    std::thread t2(&startServer);
    std::thread t3(&startWebInterface);
    std::thread t4(&startMinting);
    t1.join();
    t2.join();
    t3.join();
    t4.join();

    return 0;
}
