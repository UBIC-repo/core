
#include <ctime>

#if defined(_WIN32)
#include <synchapi.h>
#else
#include <unistd.h>
#endif
#include "Mint.h"
#include "../TxPool.h"
#include "../MerkleTree.h"
#include "../Chain.h"
#include "../Network/Network.h"
#include "../Tools/Log.h"
#include "../Transaction/TransactionHelper.h"
#include "../Consensus/VoteStore.h"
#include "../Time.h"
#include "../Wallet.h"
#include "../AddressHelper.h"
#include "../App.h"

Block Mint::mintBlock() {
    Log(LOG_LEVEL_INFO) << "Mint::mintBlock()";
    Block* block = new Block();
    VoteStore& voteStore = VoteStore::Instance();
    Chain& chain = Chain::Instance();
    Wallet& wallet = Wallet::Instance();
    BlockHeader* previousBlockHeader = chain.getBestBlockHeader();
    BlockHeader* blockHeader = new BlockHeader();
    blockHeader->setTimestamp(this->getTimeStamp());
    if(previousBlockHeader == nullptr) {
        blockHeader->setPreviousHeaderHash(std::vector<unsigned char>());
    } else {
        blockHeader->setPreviousHeaderHash(previousBlockHeader->getHeaderHash());
    }

    uint64_t currentTimeStamp = Time::getCurrentTimestamp();

    std::vector<unsigned char> currentValidatorPubKey = voteStore.getValidatorForTimestamp(currentTimeStamp);

    Address currentValidatorAddress = wallet.addressFromPublicKey(currentValidatorPubKey);
    std::vector<unsigned char> currentValidatorAddressLink = AddressHelper::addressLinkFromScript(currentValidatorAddress.getScript());

    if(!wallet.isMine(currentValidatorAddressLink)) {
        Log(LOG_LEVEL_INFO) << "Cannot mint a block, another node pubkey: "
                            << currentValidatorPubKey
                            << " addressLink: "
                            << currentValidatorAddressLink
                            << " is the current validator";
        return *block;
    }

    if(chain.getBestBlockHeader() != nullptr && chain.getBestBlockHeader()->getIssuerPubKey() == currentValidatorPubKey) {
        Log(LOG_LEVEL_INFO) << "Cannot mint a block, last block was minted by the same public key";
        return *block;
    }

    if(chain.getBestBlockHeader() != nullptr
       && (uint64_t)(chain.getBestBlockHeader()->getTimestamp() / BLOCK_INTERVAL_IN_SECONDS) == currentTimeStamp / BLOCK_INTERVAL_IN_SECONDS
      ) {
        Log(LOG_LEVEL_ERROR) << "Cannot mint a block, Slot number " << (uint64_t)(currentTimeStamp / BLOCK_INTERVAL_IN_SECONDS)
                             << " is already taken by another block";
        return *block;
    }

    std::vector<Transaction> transactionList;
    std::vector<Transaction> voteList;

    uint32_t blockSize = 0;
    TxPool& txPool = TxPool::Instance();

    // add a new transaction until the block is full
    while(true) {
        TransactionForNetwork* ntxForNetwork = txPool.popTransaction();

        if(ntxForNetwork == nullptr) {
            break;
        }

        Transaction ntx = ntxForNetwork->getTransaction();

        // if transaction is invalid
        if(!TransactionHelper::verifyTx(&ntx, IGNORE_IS_IN_HEADER, blockHeader)) {
            Log(LOG_LEVEL_ERROR) << "Had to remove one transaction that became invalid";
            continue;
        }

        blockSize += TransactionHelper::getTxSize(&ntx);

        // Block shouldn't be over 2mb, header shouldn't be over 20kb
        if(blockSize > (BLOCK_SIZE_MAX - 20000)) {
            Log(LOG_LEVEL_INFO) << "Minted Block is full";
            //push back transaction
            txPool.appendTransaction(*ntxForNetwork);
            break;
        }

        if(TransactionHelper::isVote(&ntx)) {
            voteList.emplace_back(ntx);
        } else {
            transactionList.emplace_back(ntx);
        }
    }

    // Check for double inputs which can only occur because of votes

    // index transaction inputs
    std::vector<std::string> txInputs;
    for(std::vector<Transaction>::iterator it = transactionList.begin(); it != transactionList.end();) {
        bool doRemove = false;
        for(TxIn txIn: it->getTxIns()) {
            auto txInputsIt = std::find(txInputs.begin(),
                                        txInputs.end(),
                                        Hexdump::vectorToHexString(txIn.getInAddress())
            );

            if(txInputsIt != txInputs.end()) {
                doRemove = true;
            }
            txInputs.emplace_back(Hexdump::vectorToHexString(txIn.getInAddress()));
        }

        if(doRemove) {
            TransactionForNetwork transactionForNetwork;
            transactionForNetwork.setTransaction(*it);
            // remove transaction from list and push it back to the TxPool
            txPool.appendTransaction(transactionForNetwork);
            it = transactionList.erase(it);
        } else {
            it++;
        }
    }

    // index vote target pubKey
    for(std::vector<Transaction>::iterator it = voteList.begin(); it != voteList.end();) {
        // Also insert and verify for target Delegate in txInputs
        Vote *vote = new Vote();

        CDataStream voScript(SER_DISK, 1);
        voScript.write((char *) it->getTxOuts().front().getScript().getScript().data(),
                       it->getTxOuts().front().getScript().getScript().size());
        voScript >> *vote;

        auto txInputsIt = std::find(txInputs.begin(),
                                    txInputs.end(),
                                    Hexdump::vectorToHexString(vote->getTargetPubKey())
        );

        txInputs.emplace_back(Hexdump::vectorToHexString(vote->getTargetPubKey()));
        it++;
    }

    // sort out doubles
    for(std::vector<Transaction>::iterator it = voteList.begin(); it != voteList.end();) {
        bool doRemove = false;
        for(TxIn txIn: it->getTxIns()) {
            auto txInputsIt = std::find(txInputs.begin(),
                                        txInputs.end(),
                                        Hexdump::vectorToHexString(txIn.getInAddress())
            );

            if(txInputsIt != txInputs.end()) {
                doRemove = true;
            }
            txInputs.emplace_back(Hexdump::vectorToHexString(txIn.getInAddress()));
        }

        if(doRemove) {
            TransactionForNetwork transactionForNetwork;
            transactionForNetwork.setTransaction(*it);
            // remove transaction from list and push it back to the TxPool
            txPool.appendTransaction(transactionForNetwork);
            it = voteList.erase(it);
        } else {
            it++;
        }
    }

    block->setTransactions(transactionList);
    std::vector<unsigned char> merkleTreeRootHash = MerkleTree::computeMerkleTreeRootValue(transactionList);

    blockHeader->setMerkleRootHash(merkleTreeRootHash);
    blockHeader->setVotes(voteList);

    blockHeader->setBlockHeight(chain.getCurrentBlockchainHeight() + 1);

    block->setHeader(blockHeader);

    UAmount32 ubiReceiverCount = BlockHelper::calculateUbiReceiverCount(block, previousBlockHeader);
    blockHeader->setUbiReceiverCount(ubiReceiverCount);

    UAmount payout;
    UAmount payoutRemainder;

    BlockHelper::calculatePayout(block, previousBlockHeader, ubiReceiverCount, payout, payoutRemainder);

    blockHeader->setPayout(payout);
    blockHeader->setPayoutRemainder(payoutRemainder);

    std::vector<unsigned char> headerHash = BlockHelper::computeBlockHeaderHash(*blockHeader);

    blockHeader->setIssuerPubKey(currentValidatorPubKey);

    blockHeader->setIssuerSignature(
            wallet.signWithAddress(currentValidatorAddressLink, headerHash)
    );
    blockHeader->setHeaderHash(headerHash);

    block->setHeader(blockHeader);

    if(!chain.connectBlock(block)) {
        Log(LOG_LEVEL_CRITICAL_ERROR) << "Failed to add our minted block to our own blockchain";
        // put transactions from Block back into TxPool
        // /!\ if there is a transaction causing this will make minting impossible
        txPool.appendTransactionsFromBlock(block);
        return *(new Block());
    }

    return *block;
}

void Mint::mintBlockAndBroadcast() {
    Block block = this->mintBlock();
    Network& network = Network::Instance();
    if(!block.getHeader()->getHeaderHash().empty()) {
        Log(LOG_LEVEL_INFO) << "Broadcasting new blockchain height:" << block.getHeader()->getBlockHeight();
        
        std::thread t1(&Network::broadCastNewBlockHeight, block.getHeader()->getBlockHeight(), block.getHeader()->getHeaderHash());
        t1.detach();
    }
}

uint64_t Mint::getTimeStamp() {
    time_t t = std::time(nullptr);
    return static_cast<uint64_t> (t);
}

void Mint::startMintingService() {
    //try to mint a block every 2 seconds
    for(;;)
    {
        App& app = App::Instance();
        if(!this->stopMint && !app.getTerminateSignal()) {
            this->mintBlockAndBroadcast();
        }

#if defined(_WIN32)
        Sleep(2000);
#else
        sleep(2);
#endif
    }
}

void Mint::startMinting() {
    this->stopMint = false;
}

void Mint::stopMinting() {
    this->stopMint = true;
}
