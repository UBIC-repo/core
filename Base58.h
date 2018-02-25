
#ifndef TX_BASE58_H
#define TX_BASE58_H

class Base58 {
public:
    static std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);
    static std::string EncodeBase58(const std::vector<unsigned char>& vch);
    static bool DecodeBase58(const unsigned char* psz, std::vector<unsigned char>& vch);
    static bool DecodeBase58(const unsigned char* b58, unsigned char* decoded, uint8_t *decodedLength);
};

#endif //TX_BASE58_H
