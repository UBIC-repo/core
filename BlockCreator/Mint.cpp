
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
#include "../CertStore/CertHelper.h"
#include "../CertStore/CertStore.h"
#include "../Scripts/AddCertificateScript.h"
#include "../Crypto/X509Helper.h"

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
    std::vector<TransactionForNetwork> toReappendInTxPool;

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

            // special case if it is a passport Transaction
            // create an add certificate transaction from the additional Payload field if present
            if(ntxForNetwork->getAdditionalPayloadType() == PAYLOAD_TYPE_DSC_CERTIFICATE
                && !ntxForNetwork->getAdditionalPayload().empty()) {

                X509 *x509 = X509Helper::vectorToCert(ntxForNetwork->getAdditionalPayload());
                if(x509 == nullptr) {
                    continue;
                }

                uint8_t currencyId = CertHelper::getCurrencyIdForCert(x509);
                if(currencyId == 0) {
                    continue;
                }

                uint64_t expiration = CertHelper::calculateDSCExpirationDateForCert(x509);
                if(expiration < Time::getCurrentTimestamp() + 600) { //expired or going to expire very soon
                    continue;
                }

                Chain& chain = Chain::Instance();
                CertStore& certStore = CertStore::Instance();

                Cert cert;
                cert.setX509(x509);
                cert.setCurrencyId(currencyId);
                cert.setExpirationDate(expiration);
                cert.appendStatusList(std::pair<uint32_t, bool>(chain.getCurrentBlockchainHeight(), true));

                if(certStore.getDscCertWithCertId(cert.getId()) != nullptr) {
                    // This case was already tested previously and if we are here it failed
                    continue;
                }

                if(!certStore.isCertSignedByCSCA(&cert, chain.getCurrentBlockchainHeight())) {
                    continue;
                }

                uint32_t nonce = 0;
                AddCertificateScript addCertificateScript;
                addCertificateScript.currency = cert.getCurrencyId();
                addCertificateScript.type = TYPE_DSC;
                addCertificateScript.expirationDate = cert.getExpirationDate();
                addCertificateScript.certificate = ntxForNetwork->getAdditionalPayload();

                CDataStream s1(SER_DISK, 1);
                s1 << addCertificateScript;

                TxIn *txIn = new TxIn();

                UAmount inAmount;
                txIn->setAmount(inAmount);
                txIn->setNonce(nonce);
                txIn->setInAddress(cert.getId());

                UScript script;
                script.setScript((unsigned char*)s1.data(), (uint16_t)s1.size());
                script.setScriptType(SCRIPT_ADD_CERTIFICATE);
                txIn->setScript(script);
                std::vector<TxIn> txIns;
                txIns.emplace_back(*txIn);

                Transaction* addDscCertificateTransaction = new Transaction();
                addDscCertificateTransaction->setNetwork(NET_CURRENT);
                addDscCertificateTransaction->setTxIns(txIns);

                transactionList.emplace_back(*addDscCertificateTransaction);

                // Place the register passport transaction back into the transaction pool
                // We'll try to include it in the next block
                toReappendInTxPool.emplace_back(*ntxForNetwork);
                continue;
            }

            Log(LOG_LEVEL_ERROR) << "Had to remove one transaction that became invalid";
            continue;
        }

        blockSize += TransactionHelper::getTxSize(&ntx);

        // Block shouldn't be over 2mb, header shouldn't be over 20kb
        if(blockSize > (BLOCK_SIZE_MAX - 20000)) {
            Log(LOG_LEVEL_INFO) << "Minted Block is full";
            //push back transaction
            txPool.appendTransaction(*ntxForNetwork, NO_BROADCAST_TRANSACTION);
            break;
        }

        if(TransactionHelper::isVote(&ntx)) {
            voteList.emplace_back(ntx);
        } else {
            transactionList.emplace_back(ntx);
        }
    }

    for (auto &ntxForNetwork : toReappendInTxPool) {
        txPool.appendTransaction(ntxForNetwork, NO_BROADCAST_TRANSACTION);
    }

    // Check for double inputs which can only occur because of votes and new passport registration protocol
    // where the DSC is embeded in the additionalPayload field

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
            txPool.appendTransaction(transactionForNetwork, NO_BROADCAST_TRANSACTION);
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
            txPool.appendTransaction(transactionForNetwork, NO_BROADCAST_TRANSACTION);
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
