#include <cstring>
#include <sstream>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "Cert.h"
#include "CertStore.h"
#include "../Crypto/Hash160.h"
#include "../Tools/Hexdump.h"
#include "../FS/FS.h"

bool Cert::calculateId() {
    if(this->id.size() == 0) {

        if(this->getX509() == nullptr) {
            Log(LOG_LEVEL_ERROR) << "X509 certificate is nullptr ";
            return false;
        }

        unsigned char fingerprint[32];
        unsigned int len = 32;

        X509_digest(this->getX509(), EVP_sha256(), fingerprint, &len);

        this->id = Hash160::hash160(std::vector<unsigned char>(fingerprint, fingerprint + len));

        ERR_print_errors_fp (stderr);
    }
    return true;
}

std::vector<unsigned char> Cert::getId() {
    if(this->calculateId()) {
        return this->id;
    }
    return std::vector<unsigned char>();
}

EVP_PKEY* Cert::getPubKey() {
    return X509_get_pubkey(this->x509);
}

std::string Cert::getIdAsHexString() {
    this->calculateId();

    std::string s = Hexdump::vectorToHexString(this->id);

    return s;
}

void Cert::prepareForSerialization(const char* certType) {
    this->calculateId();

    std::vector<unsigned char> path = FS::getX509DirectoryPath();

    std::string s = getIdAsHexString();

    path = FS::concatPaths(path, certType);
    path = FS::concatPaths(path, "/");
    path = FS::concatPaths(path, s.data());
    path = FS::concatPaths(path, ".cer");

    char pData[512];
    memcpy(pData, (char*)path.data(), path.size());
    memcpy(pData + path.size(), "\0", 1);

    Log(LOG_LEVEL_INFO) << "prepareForSerialization path: " << pData;

    FILE* file = fopen (pData , "w");
    if(file != nullptr) {
        i2d_X509_fp(file, this->x509);
        fclose(file);
    }
}

void Cert::finishDeserialization(const char* certType) {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    BIO* certbio = BIO_new(BIO_s_file());

    std::vector<unsigned char> path = FS::getX509DirectoryPath();

    std::string s = getIdAsHexString();

    path = FS::concatPaths(path, certType);
    path = FS::concatPaths(path, "/");
    path = FS::concatPaths(path, s.data());
    path = FS::concatPaths(path, ".cer");

    char cPath[512];
    FS::charPathFromVectorPath(cPath, path);

    if(BIO_read_filename(certbio, cPath) <=0) {
        Log(LOG_LEVEL_ERROR) << "failed to BIO_read_filename " << path.data();
    }

    this->x509 = d2i_X509_bio(certbio, nullptr);
    if (this->x509 == nullptr) {
        Log(LOG_LEVEL_ERROR) << "Error loading cert into memory " << path.data();
        printf("\n");
    }

    BIO_set_close(certbio, BIO_CLOSE);
    BIO_free(certbio);
}

void Cert::setId(vector<unsigned char> id) {
    Cert::id = id;
}

uint8_t Cert::getCurrencyId() {
    return currencyId;
}

void Cert::setCurrencyId(uint8_t currencyId) {
    Cert::currencyId = currencyId;
}

std::vector<std::pair<uint32_t, bool> > Cert::getStatusList() {
    return statusList;
}

void Cert::setStatusList(std::vector<std::pair<uint32_t, bool> > statusList) {
    Cert::statusList = statusList;
}

void Cert::appendStatusList(std::pair<uint32_t, bool> newStatus) {
    this->statusList.push_back(newStatus);
}

bool Cert::isCertAtive() {
    if(this->statusList.empty()) {
        return false;
    }
    return this->statusList.back().second;
}

bool Cert::isMature(uint32_t blockHeight) {

    Log(LOG_LEVEL_INFO) << "maturation for blockheight:" << blockHeight;

    if(blockHeight <= CSCA_MATURATION_SUSPENSIONTIME_IN_BLOCKS || this->statusList.back().first <= CSCA_MATURATION_SUSPENSIONTIME_IN_BLOCKS) {
        return true;
    }

    if(this->statusList.empty()) {
        Log(LOG_LEVEL_INFO) << "is not mature because status list is empty";
        return false;
    }

    if(!this->statusList.back().second) {
        Log(LOG_LEVEL_INFO) << "is not mature because it is deactivated" << this->statusList.end()->second;
        return false;
    }

    if((this->statusList.back().first + CSCA_MATURATION_TIME_IN_BLOCKS) <= blockHeight) {
        return true;
    }

    Log(LOG_LEVEL_INFO) << "Height " << blockHeight << " but required " << this->statusList.back().first + CSCA_MATURATION_TIME_IN_BLOCKS;

    return false;
}

uint32_t Cert::getNonce() {
    return nonce;
}

void Cert::setNonce(uint32_t nonce) {
    Cert::nonce = nonce;
}

