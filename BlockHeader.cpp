
#include <cstdint>
#include "BlockHeader.h"
#include "UAmount.h"

std::vector<unsigned char> BlockHeader::getHeaderHash() {
    return headerHash;
}

void BlockHeader::setHeaderHash(std::vector<unsigned char> headerHash) {
    this->headerHash = headerHash;
}

std::vector<unsigned char> BlockHeader::getPreviousHeaderHash() {
    return previousHeaderHash;
}

void BlockHeader::setPreviousHeaderHash(std::vector<unsigned char> previousHeaderHash) {
    this->previousHeaderHash = previousHeaderHash;
}

const std::vector<unsigned char> BlockHeader::getMerkleRootHash() {
    return merkleRootHash;
}

void BlockHeader::setMerkleRootHash(std::vector<unsigned char> merkleRootHash) {
    this->merkleRootHash = merkleRootHash;
}

uint32_t BlockHeader::getBlockHeight() {
    return blockHeight;
}

void BlockHeader::setBlockHeight(uint64_t blockHeight) {
    this->blockHeight = blockHeight;
}

uint32_t BlockHeader::getTimestamp() {
    return timestamp;
}

void BlockHeader::setTimestamp(uint64_t timestamp) {
    this->timestamp = timestamp;
}

const UAmount BlockHeader::getPayout() {
    return payout;
}

void BlockHeader::setPayout(UAmount payout) {
    this->payout = payout;
}

std::vector<unsigned char> BlockHeader::getIssuerPubKey() {
    return issuerPubKey;
}

void BlockHeader::setIssuerPubKey(std::vector<unsigned char> issuerPubKey) {
    this->issuerPubKey = issuerPubKey;
}

std::vector<unsigned char> BlockHeader::getIssuerSignature() {
    return issuerSignature;
}

void BlockHeader::setIssuerSignature(std::vector<unsigned char> issuerSignature) {
    this->issuerSignature = issuerSignature;
}

UAmount32 BlockHeader::getUbiReceiverCount() {
    return ubiReceiverCount;
}

void BlockHeader::setUbiReceiverCount(UAmount32 ubiReceiverCount) {
    this->ubiReceiverCount = ubiReceiverCount;
}

UAmount BlockHeader::getPayoutRemainder() {
    return payoutRemainder;
}

void BlockHeader::setPayoutRemainder(UAmount payoutRemainder) {
    this->payoutRemainder = payoutRemainder;
}

bool BlockHeader::isIsValid() {
    return isValid;
}

void BlockHeader::setIsValid(bool isValid) {
    this->isValid = isValid;
}

uint8_t BlockHeader::getVersion() const {
    return this->version;
}

void BlockHeader::setVersion(uint8_t version) {
    this->version = version;
}

const std::vector<Transaction> &BlockHeader::getVotes() const {
    return this->votes;
}

void BlockHeader::setVotes(const std::vector<Transaction> &votes) {
    this->votes = votes;
}
