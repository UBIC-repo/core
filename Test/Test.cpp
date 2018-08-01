
#include <openssl/err.h>
#include "Test.h"
#include "../FS/FS.h"
#include "../CertStore/CertStore.h"
#include "../Crypto/CreateSignature.h"
#include "../Transaction/TxOut.h"
#include "../Transaction/Transaction.h"
#include "../TxPool.h"
#include "../Wallet.h"
#include "../Time.h"

uint8_t Test::getCurrencyIdFromIso2Code(char* iso2code) {
    uint8_t currencyId = 0;
    if(strcmp(iso2code, "AT") == 0 || strcmp(iso2code, "at") == 0) {
        currencyId = CURRENCY_AUSTRIA;
    }

    if(strcmp(iso2code, "DE") == 0 || strcmp(iso2code, "de") == 0) {
        currencyId = CURRENCY_GERMANY;
    }

    if(strcmp(iso2code, "FR") == 0 || strcmp(iso2code, "fr") == 0) {
        currencyId = CURRENCY_FRANCE;
    }

    if(strcmp(iso2code, "SE") == 0 || strcmp(iso2code, "se") == 0) {
        currencyId = CURRENCY_SWEDEN;
    }

    if(strcmp(iso2code, "CA") == 0 || strcmp(iso2code, "ca") == 0) {
        currencyId = CURRENCY_CANADA;
    }

    if(strcmp(iso2code, "IE") == 0 || strcmp(iso2code, "ie") == 0) {
        currencyId = CURRENCY_IRELAND;
    }

    if(strcmp(iso2code, "CN") == 0 || strcmp(iso2code, "cn") == 0) {
        currencyId = CURRENCY_CHINA;
    }

    if(strcmp(iso2code, "GB") == 0 || strcmp(iso2code, "gb") == 0) {
        currencyId = CURRENCY_UNITED_KINGDOM;
    }

    if(strcmp(iso2code, "AE") == 0 || strcmp(iso2code, "ae") == 0) {
        currencyId = CURRENCY_UNITED_ARAB_EMIRATES;
    }

    if(strcmp(iso2code, "NZ") == 0 || strcmp(iso2code, "nz") == 0) {
        currencyId = CURRENCY_NEW_ZEALAND;
    }

    if(strcmp(iso2code, "FI") == 0 || strcmp(iso2code, "fi") == 0) {
        currencyId = CURRENCY_FINLAND;
    }

    if(strcmp(iso2code, "LU") == 0 || strcmp(iso2code, "lu") == 0) {
        currencyId = CURRENCY_LUXEMBOURG;
    }

    if(strcmp(iso2code, "SG") == 0 || strcmp(iso2code, "sg") == 0) {
        currencyId = CURRENCY_SINGAPORE;
    }

    if(strcmp(iso2code, "HU") == 0 || strcmp(iso2code, "hu") == 0) {
        currencyId = CURRENCY_HUNGARY;
    }

    if(strcmp(iso2code, "CZ") == 0 || strcmp(iso2code, "cz") == 0) {
        currencyId = CURRENCY_CZECH_REPUBLIC;
    }

    if(strcmp(iso2code, "MY") == 0 || strcmp(iso2code, "my") == 0) {
        currencyId = CURRENCY_MALAYSIA;
    }

    if(strcmp(iso2code, "UA") == 0 || strcmp(iso2code, "ua") == 0) {
        currencyId = CURRENCY_UKRAINE;
    }

    if(strcmp(iso2code, "EE") == 0 || strcmp(iso2code, "ee") == 0) {
        currencyId = CURRENCY_ESTONIA;
    }

    if(strcmp(iso2code, "MC") == 0 || strcmp(iso2code, "mc") == 0) {
        currencyId = CURRENCY_MONACO;
    }

    if(strcmp(iso2code, "LI") == 0 || strcmp(iso2code, "li") == 0) {
        currencyId = CURRENCY_LIECHTENSTEIN;
    }

    if(strcmp(iso2code, "US") == 0 || strcmp(iso2code, "us") == 0) {
        currencyId = CURRENCY_USA;
    }

    if(strcmp(iso2code, "AU") == 0 || strcmp(iso2code, "au") == 0) {
        currencyId = CURRENCY_AUSTRALIA;
    }

    if(strcmp(iso2code, "CH") == 0) {
        currencyId = CURRENCY_SWITZERLAND;
    }

    if(strcmp(iso2code, "JP") == 0) {
        currencyId = CURRENCY_JAPAN;
    }

    if(strcmp(iso2code, "TH") == 0) {
        currencyId = CURRENCY_THAILAND;
    }

    return currencyId;
}

time_t Test::ASN1_GetTimeT(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}

void Test::importCACerts() {

    std::vector<unsigned char> privKey = Hexdump::hexStringToVector(UBIC_ROOT_PRIVATE_KEY);

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

            if(getCurrencyIdFromIso2Code((char*)countryStr) == 0) {
                Log(LOG_LEVEL_INFO) << "Could not get currency ID for countryStr:" << countryStr;
                return;
                continue;
            }

            time_t notAfterTime = Test::ASN1_GetTimeT(notAfter);

            uint64_t notAfter64 = *reinterpret_cast<uint64_t*>(&notAfterTime);

            if(notAfter64 < Time::getCurrentTimestamp()) {
                Log(LOG_LEVEL_ERROR) << "Certificate " << pData << " is expired";
                continue;
            }

            ca->setExpirationDate(notAfter64);
            ca->setCurrencyId(Test::getCurrencyIdFromIso2Code((char*)countryStr));

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

            txPool.appendTransaction(*tx);
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
        std::vector<std::vector<unsigned char> > fileList2 = FS::readDir(file);

        for(std::vector<unsigned char> file2: fileList2) {
            char pData[512];
            memcpy(pData, (char*)file2.data(), file2.size());
            memcpy(pData + file2.size(), "\0", 1);

            Cert* dsc = CertStore::certFromFile(pData);
            Log(LOG_LEVEL_INFO) << "DSC path:" << pData;

            X509* x509 = dsc->getX509();
            ASN1_TIME* notAfter = X509_getm_notAfter(x509);
            ASN1_TIME* notBefore = X509_getm_notBefore(x509);
            X509_NAME *subject = X509_get_subject_name(x509);

            X509_NAME_ENTRY *country = X509_NAME_get_entry(subject, 0);
            ASN1_STRING *countryData = X509_NAME_ENTRY_get_data(country);
            const unsigned char *countryStr = ASN1_STRING_get0_data(countryData);

            Log(LOG_LEVEL_INFO) << "Country code: " << countryStr;

            if(getCurrencyIdFromIso2Code((char*)countryStr) == 0) {
                Log(LOG_LEVEL_INFO) << "Could not get currency ID for countryStr:" << countryStr;
                return;
            }

            Log(LOG_LEVEL_INFO) << "notAfter: " << notAfter->data;
            Log(LOG_LEVEL_INFO) << "notBefore: " << notBefore->data;

            time_t notAfterTime = Test::ASN1_GetTimeT(notAfter);
            time_t notBeforeTime = Test::ASN1_GetTimeT(notBefore);

            uint64_t notAfter64 = *reinterpret_cast<uint64_t*>(&notAfterTime);
            uint64_t notBefore64 = *reinterpret_cast<uint64_t*>(&notBeforeTime);

            Log(LOG_LEVEL_INFO) << "notAfter: " << notAfter64;
            Log(LOG_LEVEL_INFO) << "notBefore: " << notBefore64;

            uint32_t maxValidity = 0;
            uint8_t currencyId = Test::getCurrencyIdFromIso2Code((char*)countryStr);
            uint32_t tenYears = 10 * 365 * 24 * 3600;
            uint32_t fiveYears = 5 * 365 * 24 * 3600;

            if(strcmp((char*)countryStr, "AT") == 0 || strcmp((char*)countryStr, "at") == 0 ||
               strcmp((char*)countryStr, "DE") == 0 || strcmp((char*)countryStr, "de") == 0 ||
               strcmp((char*)countryStr, "CN") == 0 || strcmp((char*)countryStr, "cn") == 0 ||
               strcmp((char*)countryStr, "GB") == 0 || strcmp((char*)countryStr, "gb") == 0 ||
               strcmp((char*)countryStr, "AU") == 0 || strcmp((char*)countryStr, "au") == 0 ||
               strcmp((char*)countryStr, "IE") == 0 || strcmp((char*)countryStr, "ie") == 0 ||
               strcmp((char*)countryStr, "NZ") == 0 || strcmp((char*)countryStr, "nz") == 0 ||
               strcmp((char*)countryStr, "CZ") == 0 || strcmp((char*)countryStr, "cz") == 0 ||
               strcmp((char*)countryStr, "CA") == 0 || strcmp((char*)countryStr, "ca") == 0 ||
               strcmp((char*)countryStr, "UA") == 0 || strcmp((char*)countryStr, "ua") == 0 ||
               strcmp((char*)countryStr, "US") == 0 || strcmp((char*)countryStr, "us") == 0 ||
               strcmp((char*)countryStr, "JP") == 0 || strcmp((char*)countryStr, "jp") == 0 ||
               strcmp((char*)countryStr, "HU") == 0 || strcmp((char*)countryStr, "hu") == 0 ||
               strcmp((char*)countryStr, "LI") == 0 || strcmp((char*)countryStr, "li") == 0 ||
               strcmp((char*)countryStr, "CH") == 0 || strcmp((char*)countryStr, "ch") == 0 ||
               strcmp((char*)countryStr, "FR") == 0 || strcmp((char*)countryStr, "fr") == 0) {
                maxValidity = tenYears;
            }

            if(strcmp((char*)countryStr, "SE") == 0 || strcmp((char*)countryStr, "se") == 0 ||
               strcmp((char*)countryStr, "FI") == 0 || strcmp((char*)countryStr, "fi") == 0 ||
               strcmp((char*)countryStr, "MY") == 0 || strcmp((char*)countryStr, "my") == 0 ||
               strcmp((char*)countryStr, "TH") == 0 || strcmp((char*)countryStr, "th") == 0 ||
               strcmp((char*)countryStr, "SG") == 0 || strcmp((char*)countryStr, "sg") == 0 ||
               strcmp((char*)countryStr, "MC") == 0 || strcmp((char*)countryStr, "mc") == 0 ||
               strcmp((char*)countryStr, "EE") == 0 || strcmp((char*)countryStr, "ee") == 0 ||
               strcmp((char*)countryStr, "LU") == 0 || strcmp((char*)countryStr, "lu") == 0 ||
               strcmp((char*)countryStr, "AE") == 0 || strcmp((char*)countryStr, "ae") == 0
               ) {
                maxValidity = fiveYears;
            }

            if(maxValidity == 0) {
                Log(LOG_LEVEL_ERROR) << "maxValidity == 0";
                continue;
            }

            uint64_t expiration = notAfter64;
            if(notBefore64 + maxValidity < expiration) {
                expiration = notBefore64 + maxValidity;
            }

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

            if(txPool.appendTransaction(*tx)) {
                Log(LOG_LEVEL_INFO) << "appended ADD Certificate to transactions";
            }
            dscCounter++;
        }
    }
    Log(LOG_LEVEL_INFO) << "added: " << dscCounter << " csca certificates";
}
