
#ifndef PASSPORTREADER_CURRENCY_H
#define PASSPORTREADER_CURRENCY_H

class Currency {
private:
    uint8_t currencyId;
    bool error = false;
public:
    uint8_t getCurrencyId() const {
        return currencyId;
    }

    void setCurrencyId(uint8_t currencyId) {
        Currency::currencyId = currencyId;
    }

    bool isError() const {
        return error;
    }

    void setError(bool error) {
        Currency::error = error;
    }
};


#endif //PASSPORTREADER_CURRENCY_H
