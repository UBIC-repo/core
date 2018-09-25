
#include <stdlib.h>
#include "Block.h"
#include "Tools/Log.h"
#include "PathSum/PathSum.h"
#include "TxPool.h"
#include "CertStore/CertStore.h"
#include "DSCAttachedPassportCounter.h"
#include "Chain.h"
#include "Crypto/Hash256.h"
#include "Crypto/VerifySignature.h"
#include "Transaction/TransactionHelper.h"
#include "AddressStore.h"
#include "Wallet.h"
#include "Consensus/VoteStore.h"
#include "Time.h"
#include "MerkleTree.h"
#include "AddressHelper.h"
#include "Scripts/AddCertificateScript.h"
#include <math.h>

BlockHeader *Block::getHeader() {
    return &header;
}

void Block::setHeader(BlockHeader *header) {
    Block::header = *header;
}

void Block::addTransaction(Transaction transaction) {
    this->transactions.emplace_back(transaction);
}

std::vector<Transaction> Block::getTransactions() {
    return transactions;
}

void Block::setTransactions(std::vector<Transaction> transactions) {
    Block::transactions = transactions;
}

bool BlockHelper::verifyBlock(Block* block) {

    Chain& chain = Chain::Instance();
    BlockHeader* header = block->getHeader();
    VoteStore& voteStore = VoteStore::Instance();
    BlockHeader* previousBlockHeader = chain.getBlockHeader(header->getPreviousHeaderHash());

    std::vector<unsigned char> computedHeaderHash = BlockHelper::computeBlockHeaderHash(*header);

    if(computedHeaderHash != header->getHeaderHash()) {
        Log(LOG_LEVEL_ERROR) << "Header hash "
                             << header->getHeaderHash()
                             << " and computed header hash "
                             << computedHeaderHash
                             << " mismatch";
        delete previousBlockHeader;
        return false;
    }

    if(header->getTimestamp() > Time::getCurrentTimestamp() + 110) {
        Log(LOG_LEVEL_ERROR) << "Timestamp of the block is in the future";
        delete previousBlockHeader;
        return false;
    }

    if(previousBlockHeader != nullptr && header->getTimestamp() <= previousBlockHeader->getTimestamp()) {
        Log(LOG_LEVEL_ERROR) << "Timestamp of the block is before previous block";
        delete previousBlockHeader;
        return false;
    }

    if(previousBlockHeader!= nullptr && header->getIssuerPubKey() == previousBlockHeader->getIssuerPubKey()) {
        Log(LOG_LEVEL_ERROR) << "Previous block was issued by the same issuer";
        delete previousBlockHeader;
        return false;
    }

    if(previousBlockHeader!= nullptr
       && (uint64_t)(header->getTimestamp() / BLOCK_INTERVAL_IN_SECONDS )== (uint64_t)(previousBlockHeader->getTimestamp() / BLOCK_INTERVAL_IN_SECONDS)
            ) {
        Log(LOG_LEVEL_ERROR) << "Slot number " << (uint64_t)(header->getTimestamp() / BLOCK_INTERVAL_IN_SECONDS)
                             << " is already taken by another block";
        delete previousBlockHeader;
        return false;
    }

    if(header->getIssuerPubKey() != voteStore.getValidatorForTimestamp(header->getTimestamp())) {
        Log(LOG_LEVEL_ERROR) << "Block issuer is: " << header->getIssuerPubKey()
                             << " but " << voteStore.getValidatorForTimestamp(header->getTimestamp())
                             << " was expected";
        delete previousBlockHeader;
        return false;
    }

    if(!VerifySignature::verify(computedHeaderHash, header->getIssuerSignature(), header->getIssuerPubKey())) {
        Log(LOG_LEVEL_ERROR) << "Block isn't signature isn't correct";
        delete previousBlockHeader;
        return false;
    }

    if(header->getVotes().size() > 0) {
        for (auto vote: header->getVotes()) {
            if(!TransactionHelper::verifyTx(&vote, IS_IN_HEADER, header)) {
                Log(LOG_LEVEL_ERROR) << "Couldn't verify Vote in block header";
                delete previousBlockHeader;
                return false;
            }
        }
    }

    std::vector<Transaction> transactions = block->getTransactions();
    std::vector<unsigned char> computedMerkleTreeRootHash =  MerkleTree::computeMerkleTreeRootValue(transactions);

    if(computedMerkleTreeRootHash != header->getMerkleRootHash()) {
        Log(LOG_LEVEL_ERROR) << "Merkle tree "
                             << header->getMerkleRootHash()
                             << " mismatch with computed merkle tree"
                             << computedMerkleTreeRootHash;
        delete previousBlockHeader;
        return false;
    }

    for(Transaction transaction: transactions) {
        if(!TransactionHelper::verifyTx(&transaction, IS_NOT_IN_HEADER, header)) {
            Log(LOG_LEVEL_ERROR) << "Failed to verify block with height "
                                 << header->getBlockHeight()
                                 << ", previous hash "
                                 << header->getPreviousHeaderHash()
                                 << " and header hash "
                                 << header->getHeaderHash()
                                 << " due to transaction";
            delete previousBlockHeader;
            return false;
        }
    }

    std::vector<Transaction> transactionsAndVotes;

    transactionsAndVotes.reserve(header->getVotes().size() + transactions.size());
    transactionsAndVotes.insert(transactionsAndVotes.end(), header->getVotes().begin(), header->getVotes().end());
    transactionsAndVotes.insert(transactionsAndVotes.end(), transactions.begin(), transactions.end());

    // Verify there aren't two transactions with the same "TxInput" in the same block
    // This ensures that two different actions are not executed on the same object in parallel
    // which could cause errors or double spends.
    // /!\ For VOTE transactions also the TxOut matters and is included in the txInputs list.
    //     Indeed by receiving a vote or an unvote the delegates state can be changed
    // /!\ PASSPORT_REGISTER transactions the passport hash is used instead of the tx input which is the DSC certificate ID
    std::vector<std::string> txInputs;
    for(Transaction transaction: transactionsAndVotes) {

        // Also insert and verify for target Delegate in txInputs
        if (TransactionHelper::isVote(&transaction)) {

            Vote *vote = new Vote();

            CDataStream voScript(SER_DISK, 1);
            voScript.write((char *) transaction.getTxOuts().front().getScript().getScript().data(),
                           transaction.getTxOuts().front().getScript().getScript().size());
            voScript >> *vote;

            auto txInputsIt = std::find(txInputs.begin(),
                                        txInputs.end(),
                                        Hexdump::vectorToHexString(vote->getTargetPubKey())
            );
            txInputs.emplace_back(Hexdump::vectorToHexString(vote->getTargetPubKey()));
        }
    }

    for(Transaction transaction: transactionsAndVotes) {
        if(TransactionHelper::isRegisterPassport(&transaction)) {
            std::vector<unsigned char> passportHash = TransactionHelper::getPassportHash(&transaction);

            auto txInputsIt = std::find(txInputs.begin(),
                                        txInputs.end(),
                                        Hexdump::vectorToHexString(passportHash)
            );

            if (txInputsIt != txInputs.end()) {
                Log(LOG_LEVEL_ERROR) << "Failed to verify block with height "
                                     << header->getBlockHeight()
                                     << ", previous hash "
                                     << header->getPreviousHeaderHash()
                                     << " and header hash "
                                     << header->getHeaderHash()
                                     << " due to duplicate input";

                delete previousBlockHeader;
                return false;
            }
            txInputs.emplace_back(Hexdump::vectorToHexString(passportHash));
        } else {
            for (TxIn txIn: transaction.getTxIns()) {
                auto txInputsIt = std::find(txInputs.begin(),
                                            txInputs.end(),
                                            Hexdump::vectorToHexString(txIn.getInAddress())
                );

                if (txInputsIt != txInputs.end()) {
                    Log(LOG_LEVEL_ERROR) << "Failed to verify block with height "
                                         << header->getBlockHeight()
                                         << ", previous hash "
                                         << header->getPreviousHeaderHash()
                                         << " and header hash "
                                         << header->getHeaderHash()
                                         << " due to duplicate input";

                    delete previousBlockHeader;
                    return false;
                }
                txInputs.emplace_back(Hexdump::vectorToHexString(txIn.getInAddress()));
            }
        }
    }

    UAmount32 calculatedUbiReceiverCount = BlockHelper::calculateUbiReceiverCount(
            block,
            previousBlockHeader
    );

    if(calculatedUbiReceiverCount != header->getUbiReceiverCount()) {
        Log(LOG_LEVEL_ERROR) << "calculatedUbiReceiverCount doesn't match header->getUbiReceiverCount()"
                             << " calculatedUbiReceiverCount is: "
                             << calculatedUbiReceiverCount
                             << " header->getUbiReceiverCount() is: "
                             << header->getUbiReceiverCount();

        delete previousBlockHeader;
        return false;
    }

    UAmount calculatedPayout;
    UAmount calculatedPayoutRemainder;

    BlockHelper::calculatePayout(
            block,
            previousBlockHeader,
            calculatedUbiReceiverCount,
            calculatedPayout,
            calculatedPayoutRemainder
    );

    if(calculatedPayout != header->getPayout()) {
        Log(LOG_LEVEL_ERROR) << "calculatedPayout doesn't match header->getPayout()"
                             << " calculatedPayout is: "
                             << calculatedPayout
                             << " header->getPayout() is: "
                             << header->getPayout();

        delete previousBlockHeader;
        return false;
    }

    if(calculatedPayoutRemainder != header->getPayoutRemainder()) {
        Log(LOG_LEVEL_ERROR) << "calculatedPayoutRemainder doesn't match header->getPayoutRemainder()"
                             << " calculatedPayoutRemainder is: "
                             << calculatedPayoutRemainder
                             << " header->getPayoutRemainder() is: "
                             << header->getPayoutRemainder();

        delete previousBlockHeader;
        return false;
    }

    delete previousBlockHeader;
    return true;
}

bool BlockHelper::applyBlock(Block* block) {
    Log(LOG_LEVEL_INFO) << "going to apply block: " << block->getHeader()->getHeaderHash();
    TxPool& txPool = TxPool::Instance();
    Wallet& wallet = Wallet::Instance();
    AddressStore& addressStore = AddressStore::Instance();

    // apply transactions
    for(Transaction transaction: block->getTransactions()) {
        TransactionHelper::applyTransaction(&transaction, block->getHeader());
        // remove transaction from transaction pool
        txPool.popTransaction(TransactionHelper::getTxId(&transaction));
    }

    // apply votes
    for(Transaction transaction: block->getHeader()->getVotes()) {
        TransactionHelper::applyTransaction(&transaction, block->getHeader());
        // remove vote from transaction pool
        txPool.popTransaction(TransactionHelper::getTxId(&transaction));
    }

    // apply payouts to PathSum
    PathSum& pathSum = PathSum::Instance();
    pathSum.appendValue(block->getHeader()->getPayout());

    // apply delegate payout
    Address delegateAddress = wallet.addressFromPublicKey(block->getHeader()->getIssuerPubKey());

    AddressForStore *delegateAddressForStore = new AddressForStore();
    delegateAddressForStore->setAmount(BlockHelper::calculateDelegatePayout(block->getHeader()->getBlockHeight()));
    delegateAddressForStore->setScript(delegateAddress.getScript());

    addressStore.creditAddressToStore(delegateAddressForStore, false);
    delete delegateAddressForStore;

    // apply dev fund payout
    Address devFundAddress = wallet.addressFromPublicKey(Hexdump::hexStringToVector(DEV_FUND_PUBLIC_KEY));

    AddressForStore *devFundAddressForStore = new AddressForStore();
    devFundAddressForStore->setAmount(BlockHelper::calculateDevFundPayout(block->getHeader()->getBlockHeight()));
    devFundAddressForStore->setScript(devFundAddress.getScript());

    addressStore.creditAddressToStore(devFundAddressForStore, false);
    delete devFundAddressForStore;

    Chain &chain = Chain::Instance();
    BlockHeader* previousBlockHeader = chain.getBlockHeader(block->getHeader()->getPreviousHeaderHash());
    CertStore& certStore = CertStore::Instance();
    std::unordered_map<std::string, Cert>* dscList = certStore.getDSCList();

    if(previousBlockHeader != nullptr) {
        // go through all DSCs to find out if one has been deactivated between previous and current block
        // @TODO this is not the most performant solution, find something better
        for(std::unordered_map<std::string, Cert>::iterator it = dscList->begin(); it != dscList->end(); ++it) {
            if(it->second.getExpirationDate() > previousBlockHeader->getTimestamp()
               && it->second.getExpirationDate() <= block->getHeader()->getTimestamp()) {

                certStore.deactivateDSC(it->second.getId(), block->getHeader()); // the certificate might already have been deactivated but that isn't an issue

                Log(LOG_LEVEL_INFO) << "DSC with id:"
                                    << it->second.getId()
                                    << " has been deactivated";
            }
        }
    }

    return true;
}

bool BlockHelper::undoBlock(Block* block) {
    Wallet& wallet = Wallet::Instance();
    AddressStore& addressStore = AddressStore::Instance();
    TxPool& txPool = TxPool::Instance();
    // undo transactions
    std::vector<Transaction> transactions = block->getTransactions();
    for(Transaction transaction: transactions) {
        TransactionHelper::undoTransaction(&transaction, block->getHeader());

        // add transaction from transaction pool
        txPool.appendTransaction(transaction);
    }

    // undo votes
    std::vector<Transaction> votes = block->getHeader()->getVotes();
    for(Transaction vote: votes) {
        TransactionHelper::undoTransaction(&vote, block->getHeader());

        // add vote from transaction pool
        txPool.appendTransaction(vote);
    }

    // undo payouts to PathSum
    PathSum& pathSum = PathSum::Instance();
    pathSum.popValue(1);

    // undo delegate payout
    Address delegateAddress = wallet.addressFromPublicKey(block->getHeader()->getIssuerPubKey());
    AddressForStore delegateAddressForStore = addressStore.getAddressFromStore(AddressHelper::addressLinkFromScript(delegateAddress.getScript()));
    delegateAddressForStore.setScript(delegateAddress.getScript());

    addressStore.debitAddressToStore(
            &delegateAddressForStore,
            BlockHelper::calculateDelegatePayout(block->getHeader()->getBlockHeight()),
            true
    );

    // undo dev fund payout
    Address devFundAddress = wallet.addressFromPublicKey(Hexdump::hexStringToVector(DEV_FUND_PUBLIC_KEY));
    AddressForStore devFundAddressForStore = addressStore.getAddressFromStore(AddressHelper::addressLinkFromScript(devFundAddress.getScript()));
    devFundAddressForStore.setScript(devFundAddress.getScript());

    addressStore.debitAddressToStore(
            &devFundAddressForStore,
            BlockHelper::calculateDevFundPayout(block->getHeader()->getBlockHeight()),
            true
    );


    Chain &chain = Chain::Instance();
    BlockHeader* previousBlockHeader = chain.getBlockHeader(block->getHeader()->getPreviousHeaderHash());
    CertStore& certStore = CertStore::Instance();
    std::unordered_map<std::string, Cert>* dscList = certStore.getDSCList();
    std::unordered_map<std::string, Cert>* cscaList = certStore.getDSCList();

    if(previousBlockHeader != nullptr) {
        // go through all DSCs to find out if one has been deactivated between previous and current block
        // @TODO this is not the most performant solution, find something better
        for (std::unordered_map<std::string, Cert>::iterator it = dscList->begin(); it != dscList->end(); ++it) {
            if (it->second.getExpirationDate() > previousBlockHeader->getTimestamp()
                && it->second.getExpirationDate() <= block->getHeader()->getTimestamp()) {

                if(certStore.undoLastActionOnDSC(it->second.getId(), CERT_ACTION_DISABLED)) {
                    Log(LOG_LEVEL_INFO) << "last action on DSC with id:"
                                        << it->second.getId()
                                        << " has undone";
                }
            }
        }

        // same with CSCAs
        for (std::unordered_map<std::string, Cert>::iterator it = cscaList->begin(); it != cscaList->end(); ++it) {
            if (it->second.getExpirationDate() > previousBlockHeader->getTimestamp()
                && it->second.getExpirationDate() <= block->getHeader()->getTimestamp()) {

                if(certStore.undoLastActionOnCSCA(it->second.getId(), CERT_ACTION_DISABLED)) {
                    Log(LOG_LEVEL_INFO) << "last action on CSCA with id:"
                                        << it->second.getId()
                                        << " has undone";
                }
            }
        }
    }

    return true;
}

UAmount BlockHelper::calculateDelegatePayout(uint32_t blockHeight) {
    uint32_t numberOfHalvings = (uint32_t)(blockHeight / HALVING_INTERVAL_IN_BLOCKS);
    int32_t halvingFactor = 1;

    for(int i = 0; i < numberOfHalvings && i < NUMBER_OF_HALVINGS; i++) {
        halvingFactor = halvingFactor * 2;
    }

    Log(LOG_LEVEL_INFO) << "BlockHelper::calculateDelegatePayout() halvingFactor:" << halvingFactor;
    Log(LOG_LEVEL_INFO) << "BlockHelper::calculateDelegatePayout() UCH payout:" << CURRENCY_SWITZERLAND_DELEGATE_PAYOUT / halvingFactor;

    UAmount amount;
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, CURRENCY_SWITZERLAND_DELEGATE_PAYOUT / halvingFactor));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, CURRENCY_GERMANY_DELEGATE_PAYOUT / halvingFactor));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, CURRENCY_AUSTRIA_DELEGATE_PAYOUT / halvingFactor));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, CURRENCY_UNITED_KINGDOM_DELEGATE_PAYOUT / halvingFactor));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, (uint64_t)(CURRENCY_IRELAND_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, (uint64_t)(CURRENCY_USA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, (uint64_t)(CURRENCY_AUSTRALIA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, (uint64_t)(CURRENCY_CHINA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, (uint64_t)(CURRENCY_SWEDEN_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, (uint64_t)(CURRENCY_FRANCE_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, (uint64_t)(CURRENCY_CANADA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, (uint64_t)(CURRENCY_JAPAN_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, (uint64_t)(CURRENCY_THAILAND_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, (uint64_t)(CURRENCY_NEW_ZEALAND_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, (uint64_t)(CURRENCY_UNITED_ARAB_EMIRATES_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, (uint64_t)(CURRENCY_FINLAND_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, (uint64_t)(CURRENCY_LUXEMBOURG_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, (uint64_t)(CURRENCY_SINGAPORE_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, (uint64_t)(CURRENCY_HUNGARY_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, (uint64_t)(CURRENCY_CZECH_REPUBLIC_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, (uint64_t)(CURRENCY_MALAYSIA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, (uint64_t)(CURRENCY_UKRAINE_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, (uint64_t)(CURRENCY_ESTONIA_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, (uint64_t)(CURRENCY_MONACO_DELEGATE_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, (uint64_t)(CURRENCY_LIECHTENSTEIN_DELEGATE_PAYOUT / halvingFactor)));

    return amount;
}

UAmount BlockHelper::calculateDevFundPayout(uint32_t blockHeight) {
    uint32_t numberOfHalvings = (uint32_t)(blockHeight / HALVING_INTERVAL_IN_BLOCKS);
    int32_t halvingFactor = 1;

    for(int i = 0; i < numberOfHalvings && i < NUMBER_OF_HALVINGS; i++) {
        halvingFactor = halvingFactor * 2;
    }

    UAmount amount;
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND,(uint64_t)( CURRENCY_SWITZERLAND_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, (uint64_t)(CURRENCY_GERMANY_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, (uint64_t)(CURRENCY_AUSTRIA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, (uint64_t)(CURRENCY_UNITED_KINGDOM_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, (uint64_t)(CURRENCY_IRELAND_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, (uint64_t)(CURRENCY_USA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, (uint64_t)(CURRENCY_AUSTRALIA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, (uint64_t)(CURRENCY_CHINA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, (uint64_t)(CURRENCY_SWEDEN_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, (uint64_t)(CURRENCY_FRANCE_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, (uint64_t)(CURRENCY_CANADA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, (uint64_t)(CURRENCY_JAPAN_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, (uint64_t)(CURRENCY_THAILAND_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, (uint64_t)(CURRENCY_NEW_ZEALAND_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, (uint64_t)(CURRENCY_UNITED_ARAB_EMIRATES_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, (uint64_t)(CURRENCY_FINLAND_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, (uint64_t)(CURRENCY_LUXEMBOURG_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, (uint64_t)(CURRENCY_SINGAPORE_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, (uint64_t)(CURRENCY_HUNGARY_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, (uint64_t)(CURRENCY_CZECH_REPUBLIC_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, (uint64_t)(CURRENCY_MALAYSIA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, (uint64_t)(CURRENCY_UKRAINE_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, (uint64_t)(CURRENCY_ESTONIA_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, (uint64_t)(CURRENCY_MONACO_DEVELOPMENT_PAYOUT / halvingFactor)));
    amount.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, (uint64_t)(CURRENCY_LIECHTENSTEIN_DEVELOPMENT_PAYOUT / halvingFactor)));

    return amount;
}

UAmount32 BlockHelper::calculateUbiReceiverCount(Block* block, BlockHeader* previousBlockHeader) {

    if(previousBlockHeader == nullptr) {
        UAmount32 newUbiReceiverCount;

        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_SWITZERLAND, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_GERMANY, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_AUSTRIA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_UNITED_KINGDOM, 0));

        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_IRELAND, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_USA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_AUSTRALIA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_CHINA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_SWEDEN, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_FRANCE, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_CANADA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_JAPAN, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_THAILAND, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_NEW_ZEALAND, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_UNITED_ARAB_EMIRATES, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_FINLAND, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_LUXEMBOURG, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_SINGAPORE, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_HUNGARY, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_CZECH_REPUBLIC, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_MALAYSIA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_UKRAINE, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_ESTONIA, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_MONACO, 0));
        newUbiReceiverCount.map.insert(std::pair<uint8_t, CAmount32>(CURRENCY_LIECHTENSTEIN, 0));

        return newUbiReceiverCount;
    }

    UAmount32 newUbiReceiverCount = previousBlockHeader->getUbiReceiverCount();

    CertStore& certStore = CertStore::Instance();
    std::unordered_map<std::string, Cert>* dscList = certStore.getDSCList();

    //go through all transactions and check for new subscriptions/certificate addition or removal
    for(Transaction transaction: block->getTransactions()) {
        for(TxIn txIn: transaction.getTxIns()) {
            if(txIn.getScript().getScriptType() == SCRIPT_REGISTER_PASSPORT) {
                Cert* cert = certStore.getDscCertWithCertId(txIn.getInAddress());
                UAmount32 toIncrement;
                toIncrement.map.insert(std::pair<uint8_t, CAmount32>(cert->getCurrencyId(), 1));
                newUbiReceiverCount += toIncrement;
            }

            if(txIn.getScript().getScriptType() == SCRIPT_ADD_CERTIFICATE) {
                AddCertificateScript addCertificateScript;
                CDataStream s(SER_DISK, 1);
                s.write((char *) txIn.getScript().getScript().data(), txIn.getScript().getScript().size());
                s >> addCertificateScript;

                if(addCertificateScript.isDSC()) {
                    Cert *cert = new Cert();
                    Currency *currency = new Currency();
                    currency->setError(false);
                    currency->setCurrencyId(addCertificateScript.currency);
                    cert->setCurrency(currency);
                    cert->setCurrencyId(addCertificateScript.currency);
                    cert->setExpirationDate(addCertificateScript.expirationDate);
                    cert->setRootSignature(addCertificateScript.rootSignature);

                    BIO *certbio = BIO_new_mem_buf(addCertificateScript.certificate.data(),
                                                   (int) addCertificateScript.certificate.size());
                    X509 *x509 = d2i_X509_bio(certbio, NULL);

                    cert->setX509(x509);

                    UAmount32 toAdd;
                    toAdd.map.insert(std::pair<uint8_t, CAmount32>(
                            cert->getCurrencyId(),
                            DSCAttachedPassportCounter::getCount(cert->getId()))
                    );
                    newUbiReceiverCount += toAdd;
                    delete cert;
                }
            }

            if(txIn.getScript().getScriptType() == SCRIPT_DEACTIVATE_CERTIFICATE) {
                DeactivateCertificateScript deactivateCertificateScript;
                CDataStream dcScript(SER_DISK, 1);
                dcScript.write((char *) txIn.getScript().getScript().data(), txIn.getScript().getScript().size());
                dcScript >> deactivateCertificateScript;
                deactivateCertificateScript.certificateId = txIn.getInAddress();
                deactivateCertificateScript.nonce = txIn.getNonce();

                if(deactivateCertificateScript.isDSC()) {
                    UAmount32 toAdd;
                    toAdd.map.insert(std::pair<uint8_t, CAmount32>(
                            certStore.getDscCertWithCertId(deactivateCertificateScript.certificateId)->getCurrencyId(),
                            DSCAttachedPassportCounter::getCount(deactivateCertificateScript.certificateId)
                    ));
                    newUbiReceiverCount += toAdd;
                }
            }

        }
    }

    // go through all DSCs to find out if one has been deactivated between previous and current block
    // @TODO this is not the most performant solution, find something better
    for(std::unordered_map<std::string, Cert>::iterator it = dscList->begin(); it != dscList->end(); ++it) {
        if(it->second.getExpirationDate() > previousBlockHeader->getTimestamp()
           && it->second.getExpirationDate() <= block->getHeader()->getTimestamp()) {
            UAmount32 toSubstract;
            toSubstract.map.insert(std::pair<uint8_t, CAmount32>(
                    it->second.getCurrencyId(),
                    DSCAttachedPassportCounter::getCount(it->second.getId()))
            );
            newUbiReceiverCount -= toSubstract;

            Log(LOG_LEVEL_INFO) << "DSC with id:"
                                << it->second.getId()
                                << " and "
                                << toSubstract
                                << " attached IDs has been deactivated";
        }
    }

    Log(LOG_LEVEL_INFO) << "newUbiReceiverCount:" << newUbiReceiverCount;

    return newUbiReceiverCount;
}

UAmount BlockHelper::getTotalPayout() {
    UAmount totalPayout;

    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, (uint64_t)(CURRENCY_SWITZERLAND_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, (uint64_t)(CURRENCY_GERMANY_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, (uint64_t)(CURRENCY_AUSTRIA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, (uint64_t)(CURRENCY_UNITED_KINGDOM_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, (uint64_t)(CURRENCY_IRELAND_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, (uint64_t)(CURRENCY_USA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, (uint64_t)(CURRENCY_AUSTRALIA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, (uint64_t)(CURRENCY_CHINA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, (uint64_t)(CURRENCY_SWEDEN_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, (uint64_t)(CURRENCY_FRANCE_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, (uint64_t)(CURRENCY_CANADA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, (uint64_t)(CURRENCY_JAPAN_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, (uint64_t)(CURRENCY_THAILAND_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, (uint64_t)(CURRENCY_NEW_ZEALAND_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, (uint64_t)(CURRENCY_UNITED_ARAB_EMIRATES_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, (uint64_t)(CURRENCY_FINLAND_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, (uint64_t)(CURRENCY_LUXEMBOURG_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, (uint64_t)(CURRENCY_SINGAPORE_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, (uint64_t)(CURRENCY_HUNGARY_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, (uint64_t)(CURRENCY_CZECH_REPUBLIC_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, (uint64_t)(CURRENCY_MALAYSIA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, (uint64_t)(CURRENCY_UKRAINE_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, (uint64_t)(CURRENCY_ESTONIA_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, (uint64_t)(CURRENCY_MONACO_EMISSION_RATE)));
    totalPayout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, (uint64_t)(CURRENCY_LIECHTENSTEIN_EMISSION_RATE)));

    return totalPayout;
}

void BlockHelper::calculatePayout(Block* block, BlockHeader* previousBlockHeader, UAmount32 newReceiverCount, UAmount &payout, UAmount &payoutRemainder) {

    if(previousBlockHeader == nullptr) {

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, 0));

        payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, 0));
        payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, 0));

        return;
    }

    UAmount totalPayout = getTotalPayout();

    totalPayout += previousBlockHeader->getPayoutRemainder();

    // -------------------------------------------------------------------------------------------------------
    uint64_t divCH = 0;
    uint64_t remCH = 0;
    if(newReceiverCount.map[CURRENCY_SWITZERLAND] != 0) {
        divCH = (uint64_t) totalPayout.map[CURRENCY_SWITZERLAND] / newReceiverCount.map[CURRENCY_SWITZERLAND];
        remCH = (uint64_t) totalPayout.map[CURRENCY_SWITZERLAND] % newReceiverCount.map[CURRENCY_SWITZERLAND];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, divCH));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWITZERLAND, remCH));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divDE = 0;
    uint64_t remDE = 0;
    if(newReceiverCount.map[CURRENCY_GERMANY] != 0) {
        divDE = (uint64_t) totalPayout.map[CURRENCY_GERMANY] / newReceiverCount.map[CURRENCY_GERMANY];
        remDE = (uint64_t) totalPayout.map[CURRENCY_GERMANY] % newReceiverCount.map[CURRENCY_GERMANY];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, divDE));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_GERMANY, remDE));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divAT = 0;
    uint64_t remAT = 0;
    if(newReceiverCount.map[CURRENCY_AUSTRIA] != 0) {
        divAT = (uint64_t) totalPayout.map[CURRENCY_AUSTRIA] / newReceiverCount.map[CURRENCY_AUSTRIA];
        remAT = (uint64_t) totalPayout.map[CURRENCY_AUSTRIA] % newReceiverCount.map[CURRENCY_AUSTRIA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, divAT));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRIA, remAT));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divUK = 0;
    uint64_t remUK = 0;
    if(newReceiverCount.map[CURRENCY_UNITED_KINGDOM] != 0) {
        divUK = (uint64_t) totalPayout.map[CURRENCY_UNITED_KINGDOM] / newReceiverCount.map[CURRENCY_UNITED_KINGDOM];
        remUK = (uint64_t) totalPayout.map[CURRENCY_UNITED_KINGDOM] % newReceiverCount.map[CURRENCY_UNITED_KINGDOM];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, divUK));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_KINGDOM, remUK));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divIE = 0;
    uint64_t remIE = 0;
    if(newReceiverCount.map[CURRENCY_IRELAND] != 0) {
        divIE = (uint64_t) totalPayout.map[CURRENCY_IRELAND] / newReceiverCount.map[CURRENCY_IRELAND];
        remIE = (uint64_t) totalPayout.map[CURRENCY_IRELAND] % newReceiverCount.map[CURRENCY_IRELAND];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, divIE));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_IRELAND, remIE));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divUS = 0;
    uint64_t remUS = 0;
    if(newReceiverCount.map[CURRENCY_USA] != 0) {
        divUS = (uint64_t) totalPayout.map[CURRENCY_USA] / newReceiverCount.map[CURRENCY_USA];
        remUS = (uint64_t) totalPayout.map[CURRENCY_USA] % newReceiverCount.map[CURRENCY_USA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, divUS));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_USA, remUS));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divAU = 0;
    uint64_t remAU = 0;
    if(newReceiverCount.map[CURRENCY_AUSTRALIA] != 0) {
        divAU = (uint64_t) totalPayout.map[CURRENCY_AUSTRALIA] / newReceiverCount.map[CURRENCY_AUSTRALIA];
        remAU = (uint64_t) totalPayout.map[CURRENCY_AUSTRALIA] % newReceiverCount.map[CURRENCY_AUSTRALIA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, divAU));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_AUSTRALIA, remAU));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divCN = 0;
    uint64_t remCN = 0;
    if(newReceiverCount.map[CURRENCY_CHINA] != 0) {
        divCN = (uint64_t) totalPayout.map[CURRENCY_CHINA] / newReceiverCount.map[CURRENCY_CHINA];
        remCN = (uint64_t) totalPayout.map[CURRENCY_CHINA] % newReceiverCount.map[CURRENCY_CHINA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, divCN));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CHINA, remCN));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divSE = 0;
    uint64_t remSE = 0;
    if(newReceiverCount.map[CURRENCY_SWEDEN] != 0) {
        divSE = (uint64_t) totalPayout.map[CURRENCY_SWEDEN] / newReceiverCount.map[CURRENCY_SWEDEN];
        remSE = (uint64_t) totalPayout.map[CURRENCY_SWEDEN] % newReceiverCount.map[CURRENCY_SWEDEN];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, divSE));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SWEDEN, remSE));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divFR = 0;
    uint64_t remFR = 0;
    if(newReceiverCount.map[CURRENCY_FRANCE] != 0) {
        divFR = (uint64_t) totalPayout.map[CURRENCY_FRANCE] / newReceiverCount.map[CURRENCY_FRANCE];
        remFR = (uint64_t) totalPayout.map[CURRENCY_FRANCE] % newReceiverCount.map[CURRENCY_FRANCE];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, divFR));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FRANCE, remFR));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divCA = 0;
    uint64_t remCA = 0;
    if(newReceiverCount.map[CURRENCY_CANADA] != 0) {
        divCA = (uint64_t) totalPayout.map[CURRENCY_CANADA] / newReceiverCount.map[CURRENCY_CANADA];
        remCA = (uint64_t) totalPayout.map[CURRENCY_CANADA] % newReceiverCount.map[CURRENCY_CANADA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, divCA));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CANADA, remCA));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divJP = 0;
    uint64_t remJP = 0;
    if(newReceiverCount.map[CURRENCY_JAPAN] != 0) {
        divJP = (uint64_t) totalPayout.map[CURRENCY_JAPAN] / newReceiverCount.map[CURRENCY_JAPAN];
        remJP = (uint64_t) totalPayout.map[CURRENCY_JAPAN] % newReceiverCount.map[CURRENCY_JAPAN];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, divJP));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_JAPAN, remJP));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divTH = 0;
    uint64_t remTH = 0;
    if(newReceiverCount.map[CURRENCY_THAILAND] != 0) {
        divTH = (uint64_t) totalPayout.map[CURRENCY_THAILAND] / newReceiverCount.map[CURRENCY_THAILAND];
        remTH = (uint64_t) totalPayout.map[CURRENCY_THAILAND] % newReceiverCount.map[CURRENCY_THAILAND];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, divTH));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_THAILAND, remTH));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divNZ = 0;
    uint64_t remNZ = 0;
    if(newReceiverCount.map[CURRENCY_NEW_ZEALAND] != 0) {
        divNZ = (uint64_t) totalPayout.map[CURRENCY_NEW_ZEALAND] / newReceiverCount.map[CURRENCY_NEW_ZEALAND];
        remNZ = (uint64_t) totalPayout.map[CURRENCY_NEW_ZEALAND] % newReceiverCount.map[CURRENCY_NEW_ZEALAND];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, divNZ));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_NEW_ZEALAND, remNZ));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divAE = 0;
    uint64_t remAE = 0;
    if(newReceiverCount.map[CURRENCY_UNITED_ARAB_EMIRATES] != 0) {
        divAE = (uint64_t) totalPayout.map[CURRENCY_UNITED_ARAB_EMIRATES] / newReceiverCount.map[CURRENCY_UNITED_ARAB_EMIRATES];
        remAE = (uint64_t) totalPayout.map[CURRENCY_UNITED_ARAB_EMIRATES] % newReceiverCount.map[CURRENCY_UNITED_ARAB_EMIRATES];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, divAE));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UNITED_ARAB_EMIRATES, remAE));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divFI = 0;
    uint64_t remFI = 0;
    if(newReceiverCount.map[CURRENCY_FINLAND] != 0) {
        divFI = (uint64_t) totalPayout.map[CURRENCY_FINLAND] / newReceiverCount.map[CURRENCY_FINLAND];
        remFI = (uint64_t) totalPayout.map[CURRENCY_FINLAND] % newReceiverCount.map[CURRENCY_FINLAND];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, divFI));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_FINLAND, remFI));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divLU = 0;
    uint64_t remLU = 0;
    if(newReceiverCount.map[CURRENCY_LUXEMBOURG] != 0) {
        divLU = (uint64_t) totalPayout.map[CURRENCY_LUXEMBOURG] / newReceiverCount.map[CURRENCY_LUXEMBOURG];
        remLU = (uint64_t) totalPayout.map[CURRENCY_LUXEMBOURG] % newReceiverCount.map[CURRENCY_LUXEMBOURG];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, divLU));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LUXEMBOURG, remLU));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divSG = 0;
    uint64_t remSG = 0;
    if(newReceiverCount.map[CURRENCY_SINGAPORE] != 0) {
        divSG = (uint64_t) totalPayout.map[CURRENCY_SINGAPORE] / newReceiverCount.map[CURRENCY_SINGAPORE];
        remSG = (uint64_t) totalPayout.map[CURRENCY_SINGAPORE] % newReceiverCount.map[CURRENCY_SINGAPORE];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, divSG));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_SINGAPORE, remSG));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divHU = 0;
    uint64_t remHU = 0;
    if(newReceiverCount.map[CURRENCY_HUNGARY] != 0) {
        divHU = (uint64_t) totalPayout.map[CURRENCY_HUNGARY] / newReceiverCount.map[CURRENCY_HUNGARY];
        remHU = (uint64_t) totalPayout.map[CURRENCY_HUNGARY] % newReceiverCount.map[CURRENCY_HUNGARY];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, divHU));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_HUNGARY, remHU));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divCZ = 0;
    uint64_t remCZ = 0;
    if(newReceiverCount.map[CURRENCY_CZECH_REPUBLIC] != 0) {
        divCZ = (uint64_t) totalPayout.map[CURRENCY_CZECH_REPUBLIC] / newReceiverCount.map[CURRENCY_CZECH_REPUBLIC];
        remCZ = (uint64_t) totalPayout.map[CURRENCY_CZECH_REPUBLIC] % newReceiverCount.map[CURRENCY_CZECH_REPUBLIC];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, divCZ));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_CZECH_REPUBLIC, remCZ));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divMY = 0;
    uint64_t remMY = 0;
    if(newReceiverCount.map[CURRENCY_MALAYSIA] != 0) {
        divMY = (uint64_t) totalPayout.map[CURRENCY_MALAYSIA] / newReceiverCount.map[CURRENCY_MALAYSIA];
        remMY = (uint64_t) totalPayout.map[CURRENCY_MALAYSIA] % newReceiverCount.map[CURRENCY_MALAYSIA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, divMY));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MALAYSIA, remMY));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divUA = 0;
    uint64_t remUA = 0;
    if(newReceiverCount.map[CURRENCY_UKRAINE] != 0) {
        divUA = (uint64_t) totalPayout.map[CURRENCY_UKRAINE] / newReceiverCount.map[CURRENCY_UKRAINE];
        remUA = (uint64_t) totalPayout.map[CURRENCY_UKRAINE] % newReceiverCount.map[CURRENCY_UKRAINE];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, divUA));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_UKRAINE, remUA));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divEE = 0;
    uint64_t remEE = 0;
    if(newReceiverCount.map[CURRENCY_ESTONIA] != 0) {
        divEE = (uint64_t) totalPayout.map[CURRENCY_ESTONIA] / newReceiverCount.map[CURRENCY_ESTONIA];
        remEE = (uint64_t) totalPayout.map[CURRENCY_ESTONIA] % newReceiverCount.map[CURRENCY_ESTONIA];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, divEE));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_ESTONIA, remEE));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divMC = 0;
    uint64_t remMC = 0;
    if(newReceiverCount.map[CURRENCY_MONACO] != 0) {
        divMC = (uint64_t) totalPayout.map[CURRENCY_MONACO] / newReceiverCount.map[CURRENCY_MONACO];
        remMC = (uint64_t) totalPayout.map[CURRENCY_MONACO] % newReceiverCount.map[CURRENCY_MONACO];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, divMC));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_MONACO, remMC));

    // -------------------------------------------------------------------------------------------------------
    uint64_t divLI = 0;
    uint64_t remLI = 0;
    if(newReceiverCount.map[CURRENCY_LIECHTENSTEIN] != 0) {
        divLI = (uint64_t) totalPayout.map[CURRENCY_LIECHTENSTEIN] / newReceiverCount.map[CURRENCY_LIECHTENSTEIN];
        remLI = (uint64_t) totalPayout.map[CURRENCY_LIECHTENSTEIN] % newReceiverCount.map[CURRENCY_LIECHTENSTEIN];
    }
    payout.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, divLI));
    payoutRemainder.map.insert(std::pair<uint8_t, CAmount>(CURRENCY_LIECHTENSTEIN, remLI));

}

std::vector<unsigned char> BlockHelper::computeBlockHeaderHash(BlockHeader header) {
    header.setHeaderHash(std::vector<unsigned char>());
    header.setIssuerSignature(std::vector<unsigned char>());
    header.setIssuerPubKey(std::vector<unsigned char>());

    CDataStream s(SER_DISK, 1);
    s << header;

    std::vector<unsigned char> s2(s.data(), s.data() + s.size());

    return Hash256::hash256(s2);
}
