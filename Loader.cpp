
#include <openssl/rand.h>
#include "Loader.h"
#include "Chain.h"
#include "FS/FS.h"
#include "CertStore/CertStore.h"
#include "PathSum/PathSum.h"
#include "Wallet.h"
#include "Consensus/VoteStore.h"
#include "Config.h"

bool Loader::createTouchFilesAndDirectories() {

    // certs/
    FS::createDirectory(FS::getCertDirectoryPath());

    // certs/root/
    FS::createDirectory(FS::concatPaths(FS::getCertDirectoryPath(), "root/"));

    // certs/csca/
    FS::createDirectory(FS::concatPaths(FS::getCertDirectoryPath(), "csca/"));

    // certs/dsc/
    FS::createDirectory(FS::concatPaths(FS::getCertDirectoryPath(), "dsc/"));

    // x509/
    FS::createDirectory(FS::getX509DirectoryPath());

    // x509/root/
    FS::createDirectory(FS::concatPaths(FS::getX509DirectoryPath(), "root/"));

    // x509/csca/
    FS::createDirectory(FS::concatPaths(FS::getX509DirectoryPath(), "csca/"));

    // x509/dsc/
    FS::createDirectory(FS::concatPaths(FS::getX509DirectoryPath(), "dsc/"));

    // blockdat/
    FS::createDirectory(FS::getBlockDatDirectoryPath());

    // AddressStore.mdb
    FS::createDirectory(FS::getAddressStorePath());

    // BlockIndexStore.mdb
    FS::createDirectory(FS::getBlockIndexStorePath());

    // NTPSKStore.mdb
    FS::createDirectory(FS::getNTPSKStorePath());

    // DSCCounterStore.mdb
    FS::createDirectory(FS::getDSCCounterStorePath());

    // blockdat/00000000.dat
    FS::touchFile(FS::getBlockDatPath());

    // wallet.dat
    FS::touchFile(FS::getWalletPath());

    // bestHeaders.dat
    FS::touchFile(FS::getBestBlockHeadersPath());

    // headers.mdb
    FS::createDirectory(FS::getBlockHeadersPath());

    // myTransactions.mdb
    FS::createDirectory(FS::getMyTransactionsPath());

    // LOGS
    FS::createDirectory(FS::getLogPath());

    return true;
}

bool Loader::isLocked() {
    return FS::fileExists(FS::getLockPath());
}

bool Loader::loadConfig() {
    if(!FS::fileExists(FS::getConfigPath())) {
        FS::createDirectory(FS::getConfigBasePath());
        FS::touchFile(FS::getConfigPath());

        uint32_t byteLength = 12;
        unsigned char buf[byteLength];
        RAND_bytes(buf, byteLength);

        std::string password = Hexdump::ucharToHexString(buf, byteLength);

        std::string config = "# the path needs to end with \"/\" if not set it will be the default one\n"
                "blockchainPath = \n"
                "\n"
                "# DANGER do not change allowFrom unless you know what you are doing\n"
                "# If you want to get remote access please consider unsing a VPN or an SSH Tunnel\n"
                "allowFrom = 127.0.0.1\n"
                "\n"
                "# The number of addresses to generate from the wallet.dat seed\n"
                "numberOfAdresses = 100\n"
                "\n"
                "# defines which events are logged\n"
                "# levels are:\n"
                "# - NOTICE\n"
                "# - INFO\n"
                "# - WARNING\n"
                "# - ERROR\n"
                "# - CRITICAL\n"
                "logLevel = NOTICE\n"
                "\n"
                "# address for donations\n"
                "donationAddress = \n"
                "\n"
                "# minting can be ON or OFF\n"
                "minting = OFF\n"
                "\n"
                "# Get nodes from Gitub\n"
                "nodesFromGithub = ON\n"
                "\n"
                "#password that needs to be send with each API request\n"
                "apiKey = ";

        //Log(LOG_LEVEL_INFO) << "Generated API password:" << password;
        std::vector<unsigned char> configVector(config.c_str(), config.c_str() + config.length());
        std::vector<unsigned char> configVector2 = FS::concatPaths(configVector, password.c_str());

        FS::overwriteFile(FS::getConfigPath(), configVector2);
    }

    Config& config = Config::Instance();
    return config.loadConfig();
}

bool Loader::loadDelegates() {
    VoteStore& voteStore = VoteStore::Instance();
    return voteStore.loadDelegates();
}

bool Loader::loadBestBlockHeaders() {
    Chain& chain = Chain::Instance();

    uint64_t pos = 0;
    bool eof = false;
    std::vector<BlockHeader> bestBlockHeaders;
    while(!eof) {
        BlockHeader* header = new BlockHeader();
        if(!FS::deserializeFromFile(FS::getBestBlockHeadersPath(), BLOCK_SIZE_MAX, pos, *header, pos, eof)) {
            break;
        }
        bestBlockHeaders.emplace_back(*header);
        chain.setCurrentBlockchainHeight(header->getBlockHeight());
    }

    if(bestBlockHeaders.empty()) {
        Log(LOG_LEVEL_INFO) << "bestBlockHeaders is empty";
        return false;
    }

    chain.setBestBlockHeaders(bestBlockHeaders);
    Log(LOG_LEVEL_INFO) << "Loaded " << bestBlockHeaders.size() << " best block header(s)";

    return true;
}

bool Loader::loadCertStore() {

    CertStore& certStore = CertStore::Instance();
    certStore.loadFromFS();

    Log(LOG_LEVEL_INFO) << "Loaded certStore";

    return true;
}

bool Loader::loadPathSum() {
    PathSum& pathSum = PathSum::Instance();
    Chain& chain = Chain::Instance();

    std::map<uint64_t, UAmount> pathSumList;

    BlockHeader* header = chain.getBestBlockHeader();
    if(header == nullptr) {
        return true;
    }
    pathSumList.insert(std::pair<uint64_t, UAmount>(header->getBlockHeight(), header->getPayout()));

    std::vector<unsigned char> previousHeaderHash = header->getPreviousHeaderHash();

    // first we insert values in a temporary variable as we start with last block and pathSum requires
    // a chronological order
    while(true) {
        //Log(LOG_LEVEL_INFO) << "previousHeaderHash: " << previousHeaderHash;
        BlockHeader* found = chain.getBlockHeader(previousHeaderHash);
        if(found == nullptr) {
            break;
        }
        //Log(LOG_LEVEL_INFO) << "Temporary inserted Payout: " << found->getPayout();
        pathSumList.insert(std::pair<uint64_t, UAmount>(found->getBlockHeight(), found->getPayout()));
        previousHeaderHash = found->getPreviousHeaderHash();
    }

    UAmount zeroBlockAmount;
    pathSum.appendValue(zeroBlockAmount); // Block zero doesn't exist so we assign empty value
    for(std::map<uint64_t, UAmount>::iterator it = pathSumList.begin(); it != pathSumList.end(); ++it) {
        pathSum.appendValue(it->second);
        //Log(LOG_LEVEL_INFO) << "Inserted Payout: " << it->second;
    }

    return true;
}

bool Loader::loadWallet() {
    Wallet& wallet = Wallet::Instance();
    wallet.initWallet();

    return true;
}
