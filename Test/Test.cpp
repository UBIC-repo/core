
#include <openssl/err.h>
#include <openssl/x509.h>
#include "Test.h"
#include "../FS/FS.h"
#include "../CertStore/CertStore.h"
#include "../Crypto/CreateSignature.h"
#include "../Transaction/TxOut.h"
#include "../Transaction/Transaction.h"
#include "../TxPool.h"
#include "../Wallet.h"
#include "../Tools/Time.h"
#include "../Scripts/AddCertificateScript.h"
#include "../CertStore/CertHelper.h"
#include "../DB/DB.h"
#include "../Consensus/Delegate.h"
#include "../Consensus/VoteStore.h"
#include "../Loader.h"

void Test::importCACerts() {

#ifdef TEST_MODE
    Wallet& wallet = Wallet::Instance();
    std::vector<unsigned char> privKey = wallet.getPrivateKeyAtPosition(0);
#else
    std::vector<unsigned char> privKey = Hexdump::hexStringToVector(UBIC_ROOT_PRIVATE_KEY);
#endif

    BIGNUM* keyBn = BN_new();
    BN_bin2bn(privKey.data(), (int)privKey.size(), keyBn);
    EC_KEY* ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, Wallet::getDefaultEcGroup());
    EC_KEY_set_private_key(ecKey, keyBn);

    EC_POINT* pubKey = EC_POINT_new(Wallet::getDefaultEcGroup());
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(Wallet::getDefaultEcGroup(), pubKey, keyBn, NULL, NULL, ctx);
    EC_KEY_set_public_key(ecKey, pubKey);

    EVP_PKEY* ubicKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(ubicKey, ecKey);

    if(!EVP_PKEY_assign_EC_KEY(ubicKey, ecKey)) {
        Log(LOG_LEVEL_ERROR) << "EVP_PKEY_assign_EC_KEY failed";
        return;
    }
/*
    BIO *bio_out;
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    EVP_PKEY_print_public(bio_out, ubicKey, 1 , NULL);
    EVP_PKEY_print_private(bio_out, ubicKey, 1 , NULL);*/

    X509 *ubicCert = CertStore::createX509(reinterpret_cast<const unsigned char*>("CH"),
                                           reinterpret_cast<const unsigned char*>("UBIC Team"),
                                           reinterpret_cast<const unsigned char*>("Root Certificate"),
                                           NULL,
                                           ubicKey
    );

    CertStore& certStore = CertStore::Instance();

    Cert* ubiCa = new Cert();
    ubiCa->setX509(ubicCert);

    std::vector<unsigned char> path = FS::getImportDirectoryPath();
    path = FS::concatPaths(path, "csca/");
    std::vector<std::vector<unsigned char> > fileList = FS::readDir(path);

    uint32_t cscaCounter = 0;

    for(std::vector<unsigned char> file: fileList) {
        Log(LOG_LEVEL_INFO) << "DIR: " <<  file.data();
        if (!FS::isDir(file)) {
            continue;
        }
        std::vector<std::vector<unsigned char> > fileList2 = FS::readDir(file);

        for(std::vector<unsigned char> file2: fileList2) {

            char pData[512];
            memcpy(pData, (char*)file2.data(), file2.size());
            memcpy(pData + file2.size(), "\0", 1);

            Log(LOG_LEVEL_INFO) << "CSCA path: " << pData;
            Cert* ca = CertStore::certFromFile(pData);

            X509* x509 = ca->getX509();
            ASN1_TIME* notAfter = X509_getm_notAfter(x509);
            ASN1_TIME* notBefore = X509_getm_notBefore(x509);
            X509_NAME *subject = X509_get_subject_name(x509);

            X509_NAME_ENTRY *country = X509_NAME_get_entry(subject, 0);
            ASN1_STRING *countryData = X509_NAME_ENTRY_get_data(country);
            const unsigned char *countryStr = ASN1_STRING_get0_data(countryData);
            Log(LOG_LEVEL_INFO) << "Country code: " << countryStr;

            if(CertHelper::getCurrencyIdForCert(x509) == 0) {
                Log(LOG_LEVEL_INFO) << "Could not get currency ID for countryStr:" << countryStr;
                return;
                continue;
            }

            time_t notAfterTime = CertHelper::ASN1_GetTimeT(notAfter);

            uint64_t notAfter64 = *reinterpret_cast<uint64_t*>(&notAfterTime);

            if(notAfter64 < Time::getCurrentTimestamp()) {
                Log(LOG_LEVEL_ERROR) << "Certificate " << pData << " is expired";
                continue;
            }

            ca->setExpirationDate(notAfter64);
            ca->setCurrencyId(CertHelper::getCurrencyIdForCert(x509));

            std::vector<unsigned char> id = ca->getId();
            Log(LOG_LEVEL_INFO) << "CSCA id: " << id;

            uint32_t nonce = 0;

            CDataStream s(SER_DISK, 1);
            s << ca->getId();
            s << ca->getExpirationDate();
            s << ca->getCurrencyId();
            s << true; //Active
            s << nonce;
            s << (uint8_t)TYPE_CSCA;

            std::vector<unsigned char> toBeSigned(s.data(), s.data() + s.size());
            Log(LOG_LEVEL_INFO) << "2 toBeSigned: " << toBeSigned;

            std::vector<unsigned char> signature = CreateSignature::sign(ubicKey, toBeSigned);
            ca->setRootSignature(signature);

            AddCertificateScript addCertificateScript;
            addCertificateScript.currency = ca->getCurrencyId();
            addCertificateScript.type = TYPE_CSCA;
            addCertificateScript.expirationDate = ca->getExpirationDate();
            addCertificateScript.rootSignature = signature;
            addCertificateScript.certificate = FS::readFile(file2);

            CDataStream s1(SER_DISK, 1);
            s1 << addCertificateScript;

            TxIn *txIn = new TxIn();

            UAmount inAmount;
            txIn->setAmount(inAmount);
            txIn->setNonce(nonce);
            txIn->setInAddress(ca->getId());

            UScript script;
            script.setScript((unsigned char*)s1.data(), (uint16_t)s1.size());
            script.setScriptType(SCRIPT_ADD_CERTIFICATE);
            txIn->setScript(script);
            std::vector<TxIn> txIns;
            txIns.emplace_back(*txIn);

            TxPool& txPool = TxPool::Instance();

            Transaction* tx = new Transaction();
            tx->setNetwork(NET_CURRENT);
            tx->setTxIns(txIns);

            TransactionForNetwork transactionForNetwork;
            transactionForNetwork.setTransaction(*tx);

            txPool.appendTransaction(transactionForNetwork, BROADCAST_TRANSACTION, nullptr);
            cscaCounter++;
            //certStore.addCSCA(ca, header);
        }
    }

    Log(LOG_LEVEL_INFO) << "added: " << cscaCounter << " csca certificates";
}

void Test::importDSCCerts() {

    std::vector<unsigned char> privKey = Hexdump::hexStringToVector(UBIC_ROOT_PRIVATE_KEY);
    BIGNUM* keyBn = BN_bin2bn(privKey.data(), (int)privKey.size(), NULL);
    EC_KEY* ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, Wallet::getDefaultEcGroup());
    EC_KEY_set_private_key(ecKey, keyBn);

    EVP_PKEY* ubicKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(ubicKey, ecKey);

    std::vector<unsigned char> path = FS::getImportDirectoryPath();
    path = FS::concatPaths(path, "dsc/");
    std::vector<std::vector<unsigned char> > fileList = FS::readDir(path);

    uint32_t dscCounter = 0;

    for(std::vector<unsigned char> file: fileList) {
        Log(LOG_LEVEL_INFO) << "DIR: " <<  file.data();
        if (!FS::isDir(file)) {
            //continue;
        }
        std::vector<std::vector<unsigned char> > fileList2 = FS::readDir(file);

        for(std::vector<unsigned char> file2: fileList2) {
            char pData[512];
            memcpy(pData, (char*)file2.data(), file2.size());
            memcpy(pData + file2.size(), "\0", 1);

            Cert* dsc = CertStore::certFromFile(pData);
            Log(LOG_LEVEL_INFO) << "DSC path:" << pData;

            X509* x509 = dsc->getX509();

            uint8_t currencyId = CertHelper::getCurrencyIdForCert(x509);

            if(currencyId == 0) {
                Log(LOG_LEVEL_INFO) << "Could not get currency ID for countryStr:" << currencyId;
                return;
                continue;
            }

            uint64_t expiration = CertHelper::calculateDSCExpirationDateForCert(x509);
            /*
            if(expiration < 1640995200) {
                expiration = Time::getCurrentTimestamp() + 540;
            }*/

            Log(LOG_LEVEL_INFO) << "expiration: " << expiration;

            if(expiration < Time::getCurrentTimestamp()) {
                Log(LOG_LEVEL_ERROR) << "Certificate " << pData << " is expired";
                continue;
            }

            dsc->setExpirationDate(expiration);
            dsc->setCurrencyId(currencyId);

            uint32_t nonce = 0;

            CDataStream s(SER_DISK, 1);
            s << dsc->getId();
            s << dsc->getExpirationDate();
            s << dsc->getCurrencyId();
            s << true; //Active
            s << nonce;
            s << (uint8_t)TYPE_DSC;

            Log(LOG_LEVEL_INFO) << "azr 1:" << Hexdump::ucharToHexString((unsigned char*)s.data(), (uint32_t)s.size());

            std::vector<unsigned char> toBeSigned(s.data(), s.data() + s.size());

            std::vector<unsigned char> signature = CreateSignature::sign(ubicKey, toBeSigned);
            dsc->setRootSignature(signature);

            Log(LOG_LEVEL_INFO) << "Certificate ID: " << dsc->getId();

            //if(dsc->getId() == Hexdump::hexStringToVector("12123123")) {
            //    return;
            //}

            AddCertificateScript addCertificateScript;
            addCertificateScript.currency = dsc->getCurrencyId();
            addCertificateScript.type = TYPE_DSC;
            addCertificateScript.expirationDate = dsc->getExpirationDate();
            addCertificateScript.rootSignature = signature;
            addCertificateScript.certificate = FS::readFile(file2);

            CDataStream s1(SER_DISK, 1);
            s1 << addCertificateScript;

            TxIn *txIn = new TxIn();

            UAmount inAmount;
            txIn->setAmount(inAmount);
            txIn->setNonce(nonce);
            txIn->setInAddress(dsc->getId());

            UScript script;
            script.setScript((unsigned char*)s1.data(), (uint16_t)s1.size());
            script.setScriptType(SCRIPT_ADD_CERTIFICATE);
            txIn->setScript(script);
            std::vector<TxIn> txIns;
            txIns.emplace_back(*txIn);

            TxPool& txPool = TxPool::Instance();

            Transaction* tx = new Transaction();
            tx->setNetwork(NET_CURRENT);
            tx->setTxIns(txIns);

            TransactionForNetwork transactionForNetwork;
            transactionForNetwork.setTransaction(*tx);

            if(txPool.appendTransaction(transactionForNetwork, BROADCAST_TRANSACTION, nullptr)) {
                Log(LOG_LEVEL_INFO) << "appended ADD Certificate to transactions";
            }
            dscCounter++;
        }
    }
    Log(LOG_LEVEL_INFO) << "added: " << dscCounter << " dsc certificates";
}

void Test::createRootCert() {
    // use first wallet address for it


    Wallet& wallet = Wallet::Instance();

    X509 *ubicRootCert = create509(reinterpret_cast<const unsigned char*>("CH"),
                                   reinterpret_cast<const unsigned char*>("UBIC Team"),
                                   reinterpret_cast<const unsigned char*>("Testing Root Certificate"),
                                   NULL,
                                   NULL,
                                   wallet.getPrivateKeyAtPosition(0)
    );

    if(ubicRootCert != nullptr) {
        CertStore& certStore = CertStore::Instance();
        Cert cert;
        cert.setX509(ubicRootCert);
        cert.setCurrencyId(0);
        cert.setExpirationDate(Time::getCurrentTimestamp() + 60*60*24*365*10);

        certStore.addUBICrootCert(&cert, 0);
    }
}

void Test::createValidators() {
    // use the 10 first wallet addresses for it

    Wallet& wallet = Wallet::Instance();
    DB& db = DB::Instance();

    for(int i = 0; i < 10; i++) {
        std::vector<unsigned char> publicKey = wallet.getPublicKeyAtPosition(i);
        Delegate targetDelegate;

        targetDelegate.setPublicKey(publicKey);
        targetDelegate.setNonce(0);
        targetDelegate.setBlockHashLastVote(std::vector<unsigned char>());
        targetDelegate.setVoteCount(10);
        targetDelegate.setUnVoteCount(0);

        if(!db.serializeToDb(DB_VOTES, publicKey, targetDelegate)) {
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot serialize delegate to DB";
        }
    }

    VoteStore& voteStore = VoteStore::Instance();
    voteStore.loadDelegates(); // reload delegates
}


X509* Test::create509(const unsigned char* c, const unsigned char* cn1, const unsigned char* cn2, X509* signer, EVP_PKEY *signerPkey, std::vector<unsigned char> privateKeyVector) {

    EVP_PKEY* pkey = EVP_PKEY_new();
    Wallet::privateKeyFromVector(pkey, privateKeyVector);

    X509 *x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509),1);
    X509_gmtime_adj(X509_get_notBefore(x509),0);
    X509_gmtime_adj(X509_get_notAfter(x509),(long)60*60*24*365*10);
    X509_set_pubkey(x509,pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME *issuerName = NULL;

    X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, cn1, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, cn2, -1, -1, 0);
    X509_set_subject_name(x509, name);

    if(signer == NULL) {
        issuerName = X509_get_subject_name(x509); //self signed
    } else {
        issuerName = X509_get_subject_name(signer);
    }
    X509_set_issuer_name(x509,issuerName);

    if(signerPkey == NULL) {
        if (X509_sign(x509, pkey, EVP_sha384())) {
            Log(LOG_LEVEL_INFO) << "Successfully signed self signed certificate";
        } else {
            Log(LOG_LEVEL_ERROR) << "Failed to self sign certificate";
        }
    } else {
        if (X509_sign(x509, signerPkey, EVP_sha384())) {
            Log(LOG_LEVEL_INFO) << "Successfully signed certificate";
        } else {
            Log(LOG_LEVEL_ERROR) << "Failed to  sign certificate";
        }
    }

    return x509;
}

void Test::sanitizeUbicFolder() {
    FS::createDirectory(FS::getBasePath());
    Loader::createTouchFilesAndDirectories();
    FS::deleteDir(FS::getBlockIndexStorePath());
    FS::deleteDir(FS::getBlockDatPath());
    FS::deleteDir(FS::getCertDirectoryPath());
    FS::deleteDir(FS::getX509DirectoryPath());
    FS::deleteDir(FS::getAddressStorePath());
    FS::deleteDir(FS::getVotesPath());
    FS::deleteDir(FS::getDSCCounterStorePath());
    FS::deleteDir(FS::getNTPSKStorePath());
    FS::deleteDir(FS::getMyTransactionsPath());
    FS::deleteFile(FS::getBestBlockHeadersPath());
}
