#ifndef UBICD_TRANSACTIONERROR_H
#define UBICD_TRANSACTIONERROR_H

#include <cstdint>
#include <string>

class TransactionError {
private:
    uint16_t errorCode = 0;
    std::string errorMessage;
    std::string additionalDetails1;
    std::string additionalDetails2;
public:
    uint16_t getErrorCode() const {
        return errorCode;
    }

    void setErrorCode(uint16_t errorCode) {
        TransactionError::errorCode = errorCode;
    }

    const std::string &getErrorMessage() const {
        return errorMessage;
    }

    void setErrorMessage(const std::string &errorMessage) {
        TransactionError::errorMessage = errorMessage;
    }

    const std::string &getAdditionalDetails1() const {
        return additionalDetails1;
    }

    void setAdditionalDetails1(const std::string &additionalDetails1) {
        TransactionError::additionalDetails1 = additionalDetails1;
    }

    const std::string &getAdditionalDetails2() const {
        return additionalDetails2;
    }

    void setAdditionalDetails2(const std::string &additionalDetails2) {
        TransactionError::additionalDetails2 = additionalDetails2;
    }
};

#endif //UBICD_TRANSACTIONERROR_H
