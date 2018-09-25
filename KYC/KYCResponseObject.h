
#ifndef UBICD_KYCRESPONSEOJECT_H
#define UBICD_KYCRESPONSEOJECT_H

#include <string>
#include <vector>

class KYCResponseObject {
private:
    bool success;
    bool dg1Success;
    bool dg2Success;
    std::string name;
    std::string dateOfBirth;
    std::string dateOfExpiry;
    std::string passportNumber;
    std::string gender;
    std::string iso2CountryCode;
    std::string image;
    std::vector<unsigned char> dg1;
    std::vector<unsigned char> dg2;
    uint8_t currencyId;
public:
    bool isSuccess() const {
        return success;
    }

    void setSuccess(bool success) {
        KYCResponseObject::success = success;
    }

    bool isDg1Success() const {
        return dg1Success;
    }

    void setDg1Success(bool dg1Success) {
        KYCResponseObject::dg1Success = dg1Success;
    }

    bool isDg2Success() const {
        return dg2Success;
    }

    void setDg2Success(bool dg2Success) {
        KYCResponseObject::dg2Success = dg2Success;
    }

    const std::string &getName() const {
        return name;
    }

    void setName(const std::string &name) {
        KYCResponseObject::name = name;
    }

    const std::string &getDateOfBirth() const {
        return dateOfBirth;
    }

    void setDateOfBirth(const std::string &dateOfBirth) {
        KYCResponseObject::dateOfBirth = dateOfBirth;
    }

    const std::string &getDateOfExpiry() const {
        return dateOfExpiry;
    }

    void setDateOfExpiry(const std::string &dateOfExpiry) {
        KYCResponseObject::dateOfExpiry = dateOfExpiry;
    }

    const std::string &getPassportNumber() const {
        return passportNumber;
    }

    void setPassportNumber(const std::string &passportNumber) {
        KYCResponseObject::passportNumber = passportNumber;
    }

    const std::string &getImage() const {
        return image;
    }

    void setImage(const std::string &image) {
        KYCResponseObject::image = image;
    }

    const std::vector<unsigned char> &getDg1() const {
        return dg1;
    }

    void setDg1(const std::vector<unsigned char> &dg1) {
        KYCResponseObject::dg1 = dg1;
    }

    const std::vector<unsigned char> &getDg2() const {
        return dg2;
    }

    void setDg2(const std::vector<unsigned char> &dg2) {
        KYCResponseObject::dg2 = dg2;
    }

    uint8_t getCurrencyId() const {
        return currencyId;
    }

    void setCurrencyId(uint8_t currencyId) {
        KYCResponseObject::currencyId = currencyId;
    }

    const std::string &getGender() const {
        return gender;
    }

    void setGender(const std::string &gender) {
        KYCResponseObject::gender = gender;
    }

    const std::string &getIso2CountryCode() const {
        return iso2CountryCode;
    }

    void setIso2CountryCode(const std::string &iso2CountryCode) {
        KYCResponseObject::iso2CountryCode = iso2CountryCode;
    }
};


#endif //UBICD_KYCRESPONSEOJECT_H
