
#include <cstring>
#include "CertHelper.h"
#include "../ChainParams.h"
#include "../Tools/Log.h"

uint8_t CertHelper::getCurrencyIdForCert(X509* x509) {

    char* iso2code = (char*)malloc(3);

    X509_NAME *subject = X509_get_subject_name(x509);
    X509_NAME_get_text_by_NID(subject, NID_countryName, iso2code, 3);

    Log(LOG_LEVEL_INFO) << "iso2code country code: " << iso2code;

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

    if(strcmp(iso2code, "CZ") == 0 || strcmp(iso2code, "cz") == 0
       || strcmp(iso2code, "STC_DS_1") == 0) {
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

    if(strcmp(iso2code, "IS") == 0 || strcmp(iso2code, "is") == 0) {
        currencyId = CURRENCY_ICELAND;
    }

    if(strcmp(iso2code, "HK") == 0 || strcmp(iso2code, "hk") == 0) {
        currencyId = CURRENCY_HONG_KONG;
    }

    if(strcmp(iso2code, "ES") == 0 || strcmp(iso2code, "es") == 0) {
        currencyId = CURRENCY_SPAIN;
    }

    if(strcmp(iso2code, "US") == 0 || strcmp(iso2code, "us") == 0) {
        currencyId = CURRENCY_USA;
    }

    if(strcmp(iso2code, "AU") == 0 || strcmp(iso2code, "au") == 0) {
        currencyId = CURRENCY_AUSTRALIA;
    }

    if(strcmp(iso2code, "CH") == 0 || strcmp(iso2code, "ch") == 0) {
        currencyId = CURRENCY_SWITZERLAND;
    }

    if(strcmp(iso2code, "JP") == 0 || strcmp(iso2code, "jp") == 0) {
        currencyId = CURRENCY_JAPAN;
    }

    if(strcmp(iso2code, "TH") == 0 || strcmp(iso2code, "th") == 0) {
        currencyId = CURRENCY_THAILAND;
    }

    if(strcmp(iso2code, "RU") == 0 || strcmp(iso2code, "ru") == 0) {
        currencyId = CURRENCY_RUSSIA;
    }

    if(strcmp(iso2code, "IL") == 0 || strcmp(iso2code, "il") == 0) {
        currencyId = CURRENCY_ISRAEL;
    }

    if(strcmp(iso2code, "PT") == 0 || strcmp(iso2code, "pt") == 0) {
        currencyId = CURRENCY_PORTUGAL;
    }

    if(strcmp(iso2code, "DK") == 0 || strcmp(iso2code, "dk") == 0) {
        currencyId = CURRENCY_DENMARK;
    }

    if(strcmp(iso2code, "TR") == 0 || strcmp(iso2code, "tr") == 0) {
        currencyId = CURRENCY_TURKEY;
    }

    if(strcmp(iso2code, "RO") == 0 || strcmp(iso2code, "ro") == 0) {
        currencyId = CURRENCY_ROMANIA;
    }

    if(strcmp(iso2code, "PL") == 0 || strcmp(iso2code, "pl") == 0) {
        currencyId = CURRENCY_POLAND;
    }

    if(strcmp(iso2code, "NL") == 0 || strcmp(iso2code, "nl") == 0) {
        currencyId = CURRENCY_NETHERLANDS;
    }

    free(iso2code);

    return currencyId;
}

uint64_t CertHelper::calculateDSCExpirationDateForCert(X509* x509) {

    ASN1_TIME* notAfter = X509_getm_notAfter(x509);
    ASN1_TIME* notBefore = X509_getm_notBefore(x509);
    uint8_t currencyId = CertHelper::getCurrencyIdForCert(x509);

    if(currencyId == 0) {
        Log(LOG_LEVEL_INFO) << "Could not get currency ID for countryStr:" << currencyId;
        return 0;
    }

    Log(LOG_LEVEL_INFO) << "notAfter: " << notAfter->data;
    Log(LOG_LEVEL_INFO) << "notBefore: " << notBefore->data;

    time_t notAfterTime = CertHelper::ASN1_GetTimeT(notAfter);
    time_t notBeforeTime = CertHelper::ASN1_GetTimeT(notBefore);

    uint64_t notAfter64 = *reinterpret_cast<uint64_t*>(&notAfterTime);
    uint64_t notBefore64 = *reinterpret_cast<uint64_t*>(&notBeforeTime);

    Log(LOG_LEVEL_INFO) << "notAfter: " << notAfter64;
    Log(LOG_LEVEL_INFO) << "notBefore: " << notBefore64;

    uint32_t maxValidity = 0;
    uint32_t tenYears = 10 * 365 * 24 * 3600;
    uint32_t fiveYears = 5 * 365 * 24 * 3600;

    if(currencyId == CURRENCY_AUSTRIA ||
       currencyId == CURRENCY_GERMANY ||
       currencyId == CURRENCY_CHINA ||
       currencyId == CURRENCY_UNITED_KINGDOM ||
       currencyId == CURRENCY_AUSTRALIA ||
       currencyId == CURRENCY_IRELAND ||
       currencyId == CURRENCY_NEW_ZEALAND ||
       currencyId == CURRENCY_CZECH_REPUBLIC ||
       currencyId == CURRENCY_CANADA ||
       currencyId == CURRENCY_UNITED_ARAB_EMIRATES ||
       currencyId == CURRENCY_USA ||
       currencyId == CURRENCY_JAPAN ||
       currencyId == CURRENCY_HUNGARY ||
       currencyId == CURRENCY_LIECHTENSTEIN ||
       currencyId == CURRENCY_SWITZERLAND ||
       currencyId == CURRENCY_SPAIN ||
       currencyId == CURRENCY_HONG_KONG ||
       currencyId == CURRENCY_ICELAND ||
       currencyId == CURRENCY_TURKEY ||
       currencyId == CURRENCY_DENMARK ||
       currencyId == CURRENCY_ISRAEL ||
       currencyId == CURRENCY_POLAND ||
       currencyId == CURRENCY_RUSSIA ||
       currencyId == CURRENCY_ROMANIA ||
       currencyId == CURRENCY_NETHERLANDS ||
       currencyId == CURRENCY_FRANCE) {
        maxValidity = tenYears;
    }

    if(currencyId == CURRENCY_SWEDEN ||
       currencyId == CURRENCY_FINLAND ||
       currencyId == CURRENCY_MALAYSIA ||
       currencyId == CURRENCY_THAILAND ||
       currencyId == CURRENCY_SINGAPORE ||
       currencyId == CURRENCY_MONACO ||
       currencyId == CURRENCY_ESTONIA ||
       currencyId == CURRENCY_LUXEMBOURG ||
       currencyId == CURRENCY_PORTUGAL ||
       currencyId == CURRENCY_UNITED_ARAB_EMIRATES
            ) {
        maxValidity = fiveYears;
    }

    uint64_t expiration = notAfter64;
    if(notBefore64 + maxValidity < expiration) {
        expiration = notBefore64 + maxValidity;
    }

    return expiration;
}

time_t CertHelper::ASN1_GetTimeT(ASN1_TIME* time) {
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    std::memset(&t, 0, sizeof(t));

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
