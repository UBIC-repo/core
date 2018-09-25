
#ifndef UBICD_KYCRESPONSEOJECT_H
#define UBICD_KYCRESPONSEOJECT_H

#include <string>
#include <vector>

class MRZResponseObject {
private:
    bool success;
    std::string name;
    std::string dateOfBirth;
    std::string dateOfExpiry;
    std::string passportNumber;
    std::string gender;
    std::string iso2CountryCode;
public:
    bool isSuccess() const {
        return success;
    }

    void setSuccess(bool success) {
        MRZResponseObject::success = success;
    }
    
    const std::string &getName() const {
        return name;
    }

    void setName(const std::string &name) {
        MRZResponseObject::name = name;
    }

    const std::string &getDateOfBirth() const {
        return dateOfBirth;
    }

    void setDateOfBirth(const std::string &dateOfBirth) {
        MRZResponseObject::dateOfBirth = dateOfBirth;
    }

    const std::string &getDateOfExpiry() const {
        return dateOfExpiry;
    }

    void setDateOfExpiry(const std::string &dateOfExpiry) {
        MRZResponseObject::dateOfExpiry = dateOfExpiry;
    }

    const std::string &getPassportNumber() const {
        return passportNumber;
    }

    void setPassportNumber(const std::string &passportNumber) {
        MRZResponseObject::passportNumber = passportNumber;
    }

    const std::string &getGender() const {
        return gender;
    }

    void setGender(const std::string &gender) {
        MRZResponseObject::gender = gender;
    }

    const std::string &getIso2CountryCode() const {
        return iso2CountryCode;
    }

    void setIso2CountryCode(const std::string &iso2CountryCode) {
        MRZResponseObject::iso2CountryCode = iso2CountryCode;
    }
};


#endif //UBICD_KYCRESPONSEOJECT_H
