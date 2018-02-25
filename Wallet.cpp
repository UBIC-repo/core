
#include <openssl/ossl_typ.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <vector>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <leveldb/db.h>
#include "Wallet.h"
#include "Base58.h"
#include "Tools/Hexdump.h"
#include "Crypto/Sha256.h"
#include "Crypto/Ripemd160.h"
#include "Tools/Log.h"
#include "Crypto/CreateSignature.h"
#include "AddressStore.h"
#include "FS/FS.h"
#include "AddressHelper.h"
#include "Crypto/ECCtools.h"
#include "DB/DB.h"
#include "Transaction/TransactionHelper.h"
#include "Consensus/Vote.h"
#include "Crypto/Hash256.h"
#include "Config.h"
#include "Chain.h"

std::vector<unsigned char> Wallet::generateSeed() {
    unsigned char cRand[32];
    int rc = RAND_bytes(cRand, 32);

    if(rc != 1) {
        Log(LOG_LEVEL_ERROR) << "Failed to generate wallet seed";
        return std::vector<unsigned char>();
    }

    return std::vector<unsigned char>(cRand, cRand + 32);
}

bool Wallet::generateWallet() {

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("a51cee5309d072c0c3b0500d09b2ccc768ee859392a7787a18b8376e684a85e3"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("0313791962da5a4c8cd5deee3646fc6d507bbfc188813b395d0f6aa55b986a3c13"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("0966831dee5007f2a895c0c7cd4fa6f159b71fb2"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("72c3fcc0e329dc45c2aaed97ae3e18ca7251ef63"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("3b7287e2565d28e8da178c0b0942d3a37060d23a7197bb7232185cde402ed8f3"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("03bdf201fc6d2989074786c3494cb077cd1ec7709ae8c8a7e359e50eb2081ed24e"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("9794b4c564102fe11f56655d09e3011bbfb67f27"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("518a8eaf2ea95bc8569881e34979952a0856f843"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("e7c162ba3578825a17736c3b0c8ebd075462536507831fe74b3b5f0cb785b879"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("024f8285633d2366517ac60c63618f894dab924a9eb419d712a46f779b8edad24c"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("d3f3df19cc903998280d50076b8051e4b320ad3f"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("a90c68860eb3e619a039186c3907f7f01f314793"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("1df9b95dde6a4016392a1a24eb675decb55fdaa231dfd774f13a9d3bd86233f7"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("02584fd71f55fd8fa239e2b2d3183bd3a051979a2edb45184e153469f37a02c070"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("0694e97f6ee7551a4b9f94d93d3b01102369ac84"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("ca6571a4015fc74687efeba697e9498976873626"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("17c866be1639fb019bc74fe7005e00bb767466e8f4cbe90f6770841163051409"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("02963db30cd772ef55649a2fd2f29c28f6a92010401a4f9ecf676c3270c19e98ed"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("d49fc636dd9437574a000e29c1842a49970b3587"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("846bc1cf7455ba4bd2bcf8c5388520439b44f545"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("a2b685d8d48c78080cb6d7bba69afc1c0fc7a8e443e6e61d6b2e7b48c285a57a"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("03a6b836dcc0b9821f76fdf5f6c7ad4fe5f821c459229020893fe663a6c7b93106"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("4f60f973fa6433f498b995694bda20078ebbb850"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("8d28eb61b099ebd01d39a3686d822102894c1ff8"));

    this->privateKeys.emplace_back(Hexdump::hexStringToVector("762484bcc2349a44fa52781671bbadf03cf71e98d59d16f788b7c3b7230953ab"));
    this->publicKeys.emplace_back(Hexdump::hexStringToVector("0327382aa165da98965ab95db301b5b7657ffd1429b3e4252af8af0c0ff3641cee"));
    this->addressesScript.emplace_back(Hexdump::hexStringToVector("4f9519751c37a3f21d17093aae01b52f8a2cc4fe"));
    this->addressesLink.emplace_back(Hexdump::hexStringToVector("ef1440450d15d4d61e1e5ea9b5eefb5554dbc644"));

    if(!this->loadSeedFromFS()) {
        this->seed = Wallet::generateSeed();
        Log(LOG_LEVEL_INFO) << "Generated new Seed";
        this->persistSeedToFS();
    }

    Log(LOG_LEVEL_INFO) << "Seed: " << this->seed;

    std::vector<unsigned char> currentPrivKey = this->seed;

    Config& config = Config::Instance();
    Log(LOG_LEVEL_INFO) << "Going to import " << config.getNumberOfAdresses() << " addresses";
    for(int i = 0; i < config.getNumberOfAdresses(); i++) {

        currentPrivKey = Hash256::hash256(FS::concatPaths(currentPrivKey, this->seed));
        //Log(LOG_LEVEL_INFO) << "currentPrivKey: " << currentPrivKey;

        EVP_PKEY* privateKey = EVP_PKEY_new();

        BIGNUM* keyBn = BN_new();
        BN_bin2bn(currentPrivKey.data(), (int)currentPrivKey.size(), keyBn);
        EC_KEY* ecKey = EC_KEY_new();
        EC_KEY_set_group(ecKey, Wallet::getDefaultEcGroup());
        EC_KEY_set_private_key(ecKey, keyBn);

        EC_POINT* pubKey = EC_POINT_new(Wallet::getDefaultEcGroup());
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT_mul(Wallet::getDefaultEcGroup(), pubKey, keyBn, NULL, NULL, ctx);
        EC_KEY_set_public_key(ecKey, pubKey);

        EVP_PKEY_assign_EC_KEY(privateKey, ecKey);

        EC_KEY *privateEcKey = EVP_PKEY_get1_EC_KEY(privateKey);
        const BIGNUM* privateKeyBN = EC_KEY_get0_private_key(privateEcKey);
        unsigned char privateKeyChar[256];
        int length = BN_bn2bin(privateKeyBN, privateKeyChar);
        this->privateKeys.emplace_back(std::vector<unsigned char>(privateKeyChar, privateKeyChar+length));
        //Log(LOG_LEVEL_INFO) << "added privateKey " << Hexdump::ucharToHexString(privateKeyChar, length);

        const EC_POINT* pubKeyPoint = EC_KEY_get0_public_key(privateEcKey);

        std::vector<unsigned char> pubkeyVector = ECCtools::ecPointToVector(Wallet::getDefaultEcGroup(), pubKeyPoint);
        this->publicKeys.emplace_back(pubkeyVector);
        //Log(LOG_LEVEL_INFO) << "added pubkeyVector " << pubkeyVector;

        Address address = Wallet::addressFromPublicKey(pubkeyVector);
        this->addressesScript.emplace_back(address.getScript().getScript());
        //Log(LOG_LEVEL_INFO) << "added addressScript " << address.getScript().getScript();

        std::vector<unsigned char> addressLink = AddressHelper::addressLinkFromScript(address.getScript());
        this->addressesLink.emplace_back(addressLink);
        //Log(LOG_LEVEL_INFO) << "added addressLink " << addressLink;
    }

    return true;
}

bool Wallet::initWallet() {
    return this->generateWallet();

    return true;
}

bool Wallet::loadSeedFromFS() {
    return FS::deserializeFromFile(FS::getWalletPath(), this->seed, SEED_SIZE_MAX);
}

bool Wallet::persistSeedToFS() {
    return FS::serializeToFile(FS::getWalletPath(), this->seed);
}

UAmount Wallet::getBalance() {
    UAmount balance;
    for(std::vector<unsigned char> address: this->addressesLink) {
        //Log(LOG_LEVEL_INFO) << "Wallet lookup for " << address;
        AddressStore &addressStore = AddressStore::Instance();
        AddressForStore addressForStore = addressStore.getAddressFromStore(address);

        UAmount addressBalance = AddressHelper::getAmountWithUBI(&addressForStore);
        balance += addressBalance;

        if(addressBalance > 0) {
            Log(LOG_LEVEL_INFO) << "addressBalance: " << addressBalance;
        }
    }

    return balance;
}

std::vector<unsigned char> Wallet::signWithAddress(std::vector<unsigned char> address, std::vector<unsigned char> msg) {
    std::vector< std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesLink.begin(), this->addressesLink.end(), address);
    if(addressIt != this->addressesLink.end()) {
        uint32_t index = (uint32_t)(addressIt - this->addressesLink.begin());
        std::vector<unsigned char> privateKey = (std::vector<unsigned char>)this->privateKeys.at(index);
        Log(LOG_LEVEL_INFO) << "Sign with private key: " << privateKey;
        return CreateSignature::sign(privateKey, msg);
    } else {
        Log(LOG_LEVEL_ERROR) << "Address not found " << address;
        return std::vector<unsigned char> ();
    }
}

std::vector<unsigned char> Wallet::getRandomPrivateKeyFromWallet() {
    unsigned char randCharArr[4];
    RAND_bytes(randCharArr, 4);
    uint32_t randNbr = *reinterpret_cast<uint32_t*>(randCharArr);
    uint32_t selectedNbr = (uint32_t) (randNbr % this->privateKeys.size());

    return this->privateKeys.at(selectedNbr);
}

std::vector<unsigned char> Wallet::getRandomAddressScriptVectorFromWallet() {
    unsigned char randCharArr[4];
    RAND_bytes(randCharArr, 4);
    uint32_t randNbr = *reinterpret_cast<uint32_t*>(randCharArr);
    uint32_t selectedNbr = (uint32_t) (randNbr % this->addressesScript.size());

    return this->addressesScript.at(selectedNbr);
}

Address Wallet::getRandomAddressFromWallet() {
    std::vector<unsigned char> pkhScript =  Wallet::getRandomAddressScriptVectorFromWallet();
    Address address;

    UScript script;
    script.setScriptType(SCRIPT_PKH);
    script.setScript(pkhScript);
    address.setScript(script);

    return address;
}

Transaction* Wallet::signTransaction(Transaction* transaction) {
    std::vector<unsigned char> txId = TransactionHelper::getTxId(transaction);
    std::vector<TxIn> txInList;
    for(TxIn txIn: transaction->getTxIns()) {

        std::vector<unsigned char> signature = this->signWithAddress(txIn.getInAddress(), txId);

        PkhInScript pkhInScript;
        pkhInScript.setPublicKey(this->getPublicKeyFromAddressLink(txIn.getInAddress()));
        pkhInScript.setSignature(signature);
        pkhInScript.setVersion(PKH_SECP256K1_VERSION);
        CDataStream s(SER_DISK, 1);
        s << pkhInScript;

        Log(LOG_LEVEL_INFO) << "pkhInScript: " << s;
        Log(LOG_LEVEL_INFO) << "pubkey: " << this->getPublicKeyFromAddressLink(txIn.getInAddress());
        Log(LOG_LEVEL_INFO) << "signature: " << signature;

        UScript script;
        script.setScriptType(SCRIPT_PKH);
        script.setScript(std::vector<unsigned char>(s.data(), s.data() + s.size()));
        txIn.setScript(script);
        txInList.emplace_back(txIn);
    }
    transaction->setTxIns(txInList);

    return transaction;
}

Transaction* Wallet::payToTxOutputs(std::vector<TxOut> txOutputs) {
    Chain& chain = Chain::Instance();
    Transaction* tx = payToTxOutputsWithoutFees(txOutputs);

    UAmount minimumTransactionFees = TransactionHelper::calculateMinimumFee(tx, chain.getBestBlockHeader());
    Log(LOG_LEVEL_INFO) << "minimumTransactionFees:" << minimumTransactionFees;

    // increase by 10%
    for(int increaseFactor = 5; increaseFactor <= 2000; increaseFactor+=10) {
        UAmount nMinimumTransactionFees;
        for(auto cFee :minimumTransactionFees.map) {
            nMinimumTransactionFees.map.insert(std::make_pair(cFee.first, cFee.second + cFee.second * increaseFactor / 100 ));
        }

        Log(LOG_LEVEL_INFO) << "nMinimumTransactionFees:" << nMinimumTransactionFees;

        for(auto cFee :nMinimumTransactionFees.map) {
            for(auto txOut: txOutputs) {
                auto found = txOut.getAmount().map.find(cFee.first);
                if(found != txOut.getAmount().map.end()) {

                    // we add a virtual tx output that represents the transaction fee
                    std::vector <TxOut> txOuts = tx->getTxOuts();
                    UAmount virtualAmount;
                    virtualAmount.map.insert(std::make_pair(cFee.first, cFee.second));
                    TxOut virtualTxOut;
                    UScript virtualScript;
                    virtualTxOut.setScript(virtualScript);
                    virtualTxOut.setAmount(virtualAmount);
                    Log(LOG_LEVEL_INFO) << "Virtualamount: " << virtualAmount;
                    txOuts.emplace_back(virtualTxOut);

                    Transaction* txTemp = payToTxOutputsWithoutFees(txOuts);
                    if(txTemp != nullptr) {
                        // remove the virtual tx output
                        txOuts.pop_back();
                        txTemp->setTxOuts(txOuts);

                        // sign the transaction again because of the removed transaction output
                        txTemp = this->signTransaction(txTemp);

                        // try again
                        if (TransactionHelper::verifyTx(txTemp, IS_NOT_IN_HEADER, chain.getBestBlockHeader())) {
                            return txTemp;
                        } else {
                            Log(LOG_LEVEL_INFO) << "Wallet::payToTxOutputs() failed for amount:" << nMinimumTransactionFees;
                        }
                    }
                }
            }
        }
    }

    return nullptr;
}

Transaction* Wallet::payToTxOutputsWithoutFees(std::vector<TxOut> txOutputs) {
    Transaction newTransaction;
    UAmount toSpend;
    for(TxOut txOutput: txOutputs) {
        toSpend += txOutput.getAmount();
    }

    std::vector<TxIn> txInputs;
    // iterate through all addresses of the wallet
    for(std::vector<unsigned char> address: this->addressesLink) {
        UAmount addressAmountToSpend;
        AddressStore &addressStore = AddressStore::Instance();
        AddressForStore addressForStore = addressStore.getAddressFromStore(address);

        UAmount addressAmount = AddressHelper::getAmountWithUBI(&addressForStore);
        TxIn txIn;
        // iterate through all currencies of the address
        for (std::map<uint8_t, CAmount>::iterator it = addressAmount.map.begin(); it != addressAmount.map.end(); ++it)
        {
            auto cToSpend = toSpend.map.find(it->first);
            if(cToSpend != toSpend.map.end()) {
                UAmount toSubstract;
                if(it->second >= cToSpend->second) {
                    toSubstract .map.insert(std::make_pair(it->first, cToSpend->second));
                } else {
                    toSubstract .map.insert(std::make_pair(it->first, it->second));
                }
                addressAmountToSpend += toSubstract;
                toSpend -= toSubstract;
            }
        }
        if(addressAmountToSpend > 0) {
            txIn.setNonce(addressForStore.getNonce());
            txIn.setAmount(addressAmountToSpend);
            txIn.setInAddress(address);
            txInputs.emplace_back(txIn);
        }
    }

    if(toSpend != 0) {
        Log(LOG_LEVEL_ERROR) << "not enough founds";
        return nullptr;
    }

    Transaction* transaction = new Transaction();
    transaction->setTxOuts(txOutputs);
    transaction->setTxIns(txInputs);
    transaction->setNetwork(NET_CURRENT);

    transaction = this->signTransaction(transaction);

    return transaction;
}

UScript Wallet::getRandomPKHScriptFromWallet() {
    std::vector<unsigned char> randomAddressScript = this->getRandomAddressScriptVectorFromWallet();
    UScript script;
    script.setScript(randomAddressScript);
    script.setScriptType(SCRIPT_PKH);

    return script;
}

bool Wallet::isMine(UScript script) {
    if(script.getScriptType() == SCRIPT_LINK) {
        std::vector<std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesLink.begin(),
                                                                                 this->addressesLink.end(),
                                                                                 script.script);
        return addressIt != this->addressesLink.end();
    } else if (script.getScriptType() == SCRIPT_PKH) {
        std::vector<std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesScript.begin(),
                                                                                 this->addressesScript.end(),
                                                                                 script.script);
        return addressIt != this->addressesScript.end();
    } else if (script.getScriptType() == SCRIPT_VOTE) {
        Vote vote;

        CDataStream s(SER_DISK, 1);
        s.write((char*)script.getScript().data(), script.getScript().size());
        s >> vote;

        Address address = addressFromPublicKey(vote.getTargetPubKey());
        std::vector<unsigned char> addressLink = AddressHelper::addressLinkFromScript(address.getScript());

        std::vector<std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesLink.begin(),
                                                                                 this->addressesLink.end(),
                                                                                 addressLink);
        return addressIt != this->addressesLink.end();
    }

    return false;
}

bool Wallet::isMine(std::vector<unsigned char> scriptLink) {
    std::vector<std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesLink.begin(),
                                                                             this->addressesLink.end(),
                                                                             scriptLink);
    return addressIt != this->addressesLink.end();
}

std::vector<unsigned char> Wallet::getPublicKeyFromAddressLink(std::vector<unsigned char> address) {
    std::vector< std::vector<unsigned char> >::iterator addressIt = std::find(this->addressesLink.begin(), this->addressesLink.end(), address);
    if(addressIt != this->addressesLink.end()) {
        uint32_t index = (uint32_t) (addressIt - this->addressesLink.begin());
        return this->publicKeys.at(index);
    }

    return std::vector<unsigned char>();
}

Address Wallet::addressFromPublicKey(std::vector<unsigned char> publicKey) {
    std::vector<unsigned char> sha256 = Sha256::sha256(publicKey);
    std::vector<unsigned char> ripemd160 = Ripemd160::ripemd160(sha256);

    UScript* script = new UScript();
    script->setScriptType(SCRIPT_PKH);
    script->setScript(ripemd160);

    Address* addressObj = new Address();
    addressObj->setScript(*script);
    return *addressObj;
}

Address Wallet::addressFromPrivateKey(EVP_PKEY *privateKey) {

    EC_KEY *privateEcKey = EVP_PKEY_get1_EC_KEY(privateKey);
    const BIGNUM* privateKeyBN = EC_KEY_get0_private_key(privateEcKey);
    unsigned char privateKeyChar[256];
    int length = BN_bn2bin(privateKeyBN, privateKeyChar);

    const EC_POINT* pubKeyPoint = EC_KEY_get0_public_key(privateEcKey);

    std::vector<unsigned char> pubkeyVector = ECCtools::ecPointToVector(Wallet::getDefaultEcGroup(), pubKeyPoint);

    Address address = Wallet::addressFromPublicKey(pubkeyVector);

    return address;
}

std::vector<unsigned char> Wallet::addressVectorFromAddress(Address address) {
    CDataStream s(SER_DISK, 1);
    s << address;

    std::vector<unsigned char> addressVector((unsigned char*)s.data(), (unsigned char*)s.data() + s.size());
    return addressVector;
}

std::string Wallet::readableAddressFromAddress(Address address) {
    std::vector<unsigned char> addressVector = Wallet::addressVectorFromAddress(address);
    Log(LOG_LEVEL_INFO) << "addressVector:" << addressVector;
    std::vector<unsigned char> checksum = Hash256::hash256(FS::concatPaths(addressVector, "UBIC"));
    addressVector.insert(addressVector.end(), checksum.begin(), checksum.begin() + 3);

    return Base58::EncodeBase58(addressVector.data(), addressVector.data() + addressVector.size());
}

void Wallet::readableAddresstoCharAddress(std::string readableAddress, unsigned char* address, uint8_t *addressLength) {
    Base58::DecodeBase58((unsigned char*)readableAddress.c_str(), address, addressLength);
}

bool Wallet::verifyReadableAddressChecksum(std::string readableAddress) {
    Wallet& wallet = Wallet::Instance();
    std::vector<unsigned char> readableAddressVector = wallet.readableAddressToVectorAddressWithChecksum(readableAddress);
    std::vector<unsigned char> readableAddressVectorWithoutChecksum(
            readableAddressVector.begin(),
            readableAddressVector.begin() + (readableAddressVector.size() - 3)
    );

    std::vector<unsigned char> readableAddressVectorChecksum(
            readableAddressVector.begin() + (readableAddressVector.size() - 3),
            readableAddressVector.begin() + readableAddressVector.size()
    );

    Log(LOG_LEVEL_INFO) << "readableAddressVector:" << readableAddressVector;
    Log(LOG_LEVEL_INFO) << "readableAddressVectorWithoutChecksum:" << readableAddressVectorWithoutChecksum;
    Log(LOG_LEVEL_INFO) << "readableAddressVectorChecksum:" << readableAddressVectorChecksum;

    std::vector<unsigned char> entireChecksum = Hash256::hash256(FS::concatPaths(readableAddressVectorWithoutChecksum, "UBIC"));
    Log(LOG_LEVEL_INFO) << "entireChecksum:" << entireChecksum;

    std::vector<unsigned char> checksum(
            entireChecksum.begin(),
            entireChecksum.begin() + 3
    );
    Log(LOG_LEVEL_INFO) << "checksum:" << checksum;

    return readableAddressVectorChecksum == checksum;
}

std::vector<unsigned char> Wallet::readableAddressToVectorAddressWithChecksum(std::string readableAddress) {
    unsigned char address[10000];
    uint8_t addressLength;
    Base58::DecodeBase58((unsigned char*)readableAddress.c_str(), address, &addressLength);

    return std::vector<unsigned char>(address, address + addressLength);
}

std::vector<unsigned char> Wallet::readableAddressToVectorAddress(std::string readableAddress) {
    std::vector<unsigned char> addressWithChecksum = readableAddressToVectorAddressWithChecksum(readableAddress);
    std::vector<unsigned char> vectorAddress(
            addressWithChecksum.begin(),
            addressWithChecksum.begin() + (addressWithChecksum.size() - 3)
    );

    return vectorAddress;
}

EC_GROUP *Wallet::getDefaultEcGroup() {
    EC_GROUP *ecGroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    EC_GROUP_set_point_conversion_form(ecGroup, form);

    return ecGroup;
}

bool Wallet::generatePrivateKey(EVP_PKEY *privateKey) {
    EC_KEY* ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, Wallet::getDefaultEcGroup());
    EC_KEY_generate_key(ecKey);
    EVP_PKEY_assign_EC_KEY(privateKey,ecKey);

    return true;
}

std::vector<TransactionForStore> Wallet::getMyTransactions() {
    DB &db = DB::Instance();

    Log(LOG_LEVEL_INFO) << "getMyTransactions() ";

    std::vector<TransactionForStore> response;
    std::vector< std::vector<unsigned char> > keys = db.getAllKeys(DB_MY_TRANSACTIONS);

    for(std::vector<unsigned char> key : keys) {
        Log(LOG_LEVEL_INFO) << "key: " << key;
        TransactionForStore transaction;
        db.deserializeFromDb(DB_MY_TRANSACTIONS, key, transaction);
        response.emplace_back(transaction);
    }

    Log(LOG_LEVEL_INFO) << "My transactions count: " << response.size();

    return response;
}

std::vector<std::vector<unsigned char> > Wallet::getAddressesScript() {
    return addressesScript;
}

std::vector<std::vector<unsigned char> > Wallet::getAddressesLink() {
    return addressesLink;
}
