
#include "Api.h"
#include "../Chain.h"
#include "../Tools/Hexdump.h"
#include "../CertStore/CertStore.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "../Tools/Log.h"
#include "../BlockStore.h"
#include "../TxPool.h"
#include "../Wallet.h"
#include "../AddressStore.h"
#include "../AddressHelper.h"
#include "../BlockCreator/Mint.h"
#include "../Network/Network.h"
#include "../PassportReader/PKCS7/PKCS7Parser.h"
#include "../PassportReader/LDS/LDSParser.h"
#include "../PassportReader/Reader/Reader.h"
#include "../Network/Peers.h"
#include "../Transaction/TransactionHelper.h"
#include "../Consensus/VoteStore.h"
#include "../Time.h"
#include "../Network/NetworkCommands.h"
#include "../Network/BanList.h"
#include "../Crypto/CreateSignature.h"
#include "../Base64.h"
#include "../Scripts/KycRequestScript.h"
#include "../Scripts/NtpskAlreadyUsedScript.h"
#include "../KYC/MRZParser.h"
#include "../PassportReader/LDS/Iso19794Parser.h"

using boost::property_tree::ptree;

ptree error(std::string message) {
    ptree error;
    error.put("error", message);

    return error;
}

ptree uamountToPtree(UAmount uamount) {
    ptree uamountTree;

    for(std::map<uint8_t, CAmount>::iterator it = uamount.map.begin(); it != uamount.map.end(); it++) {
        if(it->second > 0) {
            uamountTree.put(std::to_string(it->first), std::to_string(it->second));
        }
    }

    return uamountTree;
}

ptree txInToPtree(TxIn txIn, bool checkIsMine) {
    ptree txInTree;

    txInTree.put("inAddress", Hexdump::vectorToHexString(txIn.getInAddress()));
    txInTree.put("scriptType", txIn.getScript().getScriptType());
    txInTree.put("script", Hexdump::vectorToHexString(txIn.getScript().getScript()));
    txInTree.push_back(std::make_pair("amount", uamountToPtree(txIn.getAmount())));
    txInTree.put("nonce", txIn.getNonce());

    if(checkIsMine) {
        Wallet& wallet = Wallet::Instance();
        txInTree.put("isMine", wallet.isMine(txIn.getInAddress()));
    }

    return txInTree;
}

ptree txOutToPtree(TxOut txOut, bool checkIsMine) {
    ptree txOutTree;

    txOutTree.put("scriptType", txOut.getScript().scriptType);
    txOutTree.put("script", Hexdump::vectorToHexString(txOut.getScript().getScript()));
    txOutTree.push_back(std::make_pair("amount", uamountToPtree(txOut.getAmount())));

    if(checkIsMine) {
        Wallet& wallet = Wallet::Instance();
        txOutTree.put("isMine", wallet.isMine(txOut.getScript()));
    }

    return txOutTree;
}

ptree statusListToPtree(std::vector<std::pair<uint32_t, bool> > statusList) {
    ptree statusListTree;

    for(auto status : statusList) {
        ptree statusTree;
        statusTree.put("blockHeight", status.first);
        statusTree.put("active", status.second);
        statusListTree.push_back(std::make_pair("", statusTree));
    }


    return statusListTree;
}

ptree txToPtree(Transaction transaction, bool checkIsMine) {
    ptree txInTree;
    ptree txOutTree;
    ptree transactionTree;
    transactionTree.put("txId", Hexdump::vectorToHexString(TransactionHelper::getTxId(&transaction)));
    transactionTree.put("network", transaction.getNetwork());

    UAmount inAmount;
    UAmount outAmount;

    for (auto txIn: transaction.getTxIns()) {
        txInTree.push_back(std::make_pair("", txInToPtree(txIn, checkIsMine)));
        inAmount += txIn.getAmount();
    }

    for (auto txOut: transaction.getTxOuts()) {
        txOutTree.push_back(std::make_pair("", txOutToPtree(txOut, checkIsMine)));
        outAmount += txOut.getAmount();
    }

    transactionTree.push_back(std::make_pair("fee", uamountToPtree(inAmount - outAmount)));
    transactionTree.push_back(std::make_pair("txIn", txInTree));
    transactionTree.push_back(std::make_pair("txOut", txOutTree));

    return transactionTree;
}

ptree uamountToPtree(UAmount32 uamount) {
    ptree uamountTree;

    for(std::map<uint8_t, CAmount32>::iterator it = uamount.map.begin(); it != uamount.map.end(); it++) {
        uamountTree.put(std::to_string(it->first), std::to_string(it->second));
    }

    return uamountTree;
}

std::string Api::vote(std::string json) {
    std::vector<unsigned char> targetPubKey;
    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    Peers &peers = Peers::Instance();
    bool success = true;

    bool removedPeer = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "targetPubKey") == 0) {
            targetPubKey = Hexdump::hexStringToVector(v.second.data());
        }
    }

    if(targetPubKey.empty()) {
        return "{\"success\": false, \"error\": \"missing targetPubKey field\"}";
    }

    TxPool& txPool = TxPool::Instance();
    Wallet& wallet = Wallet::Instance();
    VoteStore& voteStore = VoteStore::Instance();
    std::map<std::vector<unsigned char>, Delegate> activeDelegates = voteStore.getActiveDelegates();

    // get through all active delegates and verify if it is me
    for (auto activeDelegate: activeDelegates) {
        Address address = wallet.addressFromPublicKey(activeDelegate.first);
        if(wallet.isMine(address.getScript())) {
            Transaction* transaction = new Transaction();
            Vote* vote = new Vote();

            vote->setAction(VOTE_ACTION_VOTE);
            vote->setTargetPubKey(targetPubKey);

            CDataStream s(SER_DISK, 1);
            s << *vote;
            UScript outScript;
            outScript.setScript(std::vector<unsigned char>(s.data(), s.data() + s.size()));
            outScript.setScriptType(SCRIPT_VOTE);
            TxOut* txOut = new TxOut();
            txOut->setScript(outScript);

            std::vector<TxOut> txOuts;
            txOuts.push_back(*txOut);

            transaction->setTxOuts(txOuts);

            transaction->setNetwork(NET_CURRENT);

            UScript inScript;
            inScript.setScriptType(SCRIPT_VOTE);

            TxIn *txIn = new TxIn();
            txIn->setNonce(activeDelegate.second.getNonce());
            txIn->setScript(inScript);
            txIn->setInAddress(activeDelegate.second.getPublicKey());

            std::vector<TxIn> txIns;
            txIns.push_back(*txIn);

            transaction->setTxIns(txIns);

            std::vector<unsigned char> signature = wallet.signWithAddress(
                    AddressHelper::addressLinkFromScript(address.getScript()),
                    TransactionHelper::getTxId(transaction)
            );

            inScript.setScript(signature);
            TxIn txInWithSignature = transaction->getTxIns().front();
            txInWithSignature.setScript(inScript);

            std::vector<TxIn> txInsWithSignature;
            txInsWithSignature.push_back(txInWithSignature);

            transaction->setTxIns(txInsWithSignature);

            Chain& chain = Chain::Instance();
            if(TransactionHelper::verifyTx(transaction, IS_IN_HEADER, chain.getBestBlockHeader())) {
                txPool.appendTransaction(*transaction);
            } else {
                success = false;
            }
        }
    }

    if(success) {
        return "{\"success\": true}";
    } else {
        return "{\"success\": false, \"error\": \"Failed to verify transaction\"}";
    }

}

std::string Api::unvote(std::string json) {

    std::vector<unsigned char> targetPubKey;
    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    Peers &peers = Peers::Instance();
    bool success = true;

    bool removedPeer = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "targetPubKey") == 0) {
            targetPubKey = Hexdump::hexStringToVector(v.second.data());
        }
    }

    if(targetPubKey.empty()) {
        return "{\"success\": false, \"error\": \"missing targetPubKey field\"}";
    }

    TxPool& txPool = TxPool::Instance();
    Wallet& wallet = Wallet::Instance();
    VoteStore& voteStore = VoteStore::Instance();
    std::map<std::vector<unsigned char>, Delegate> activeDelegates = voteStore.getActiveDelegates();

    // get through all active delegates and verify if it is me
    for (auto activeDelegate: activeDelegates) {
        Address address = wallet.addressFromPublicKey(activeDelegate.first);
        if(wallet.isMine(address.getScript())) {
            Transaction* transaction = new Transaction();
            Vote* vote = new Vote();

            vote->setAction(VOTE_ACTION_UNVOTE);
            vote->setTargetPubKey(targetPubKey);

            CDataStream s(SER_DISK, 1);
            s << *vote;
            UScript outScript;
            outScript.setScript(std::vector<unsigned char>(s.data(), s.data() + s.size()));
            outScript.setScriptType(SCRIPT_VOTE);
            TxOut* txOut = new TxOut();
            txOut->setScript(outScript);

            std::vector<TxOut> txOuts;
            txOuts.push_back(*txOut);

            transaction->setTxOuts(txOuts);

            transaction->setNetwork(NET_CURRENT);

            UScript inScript;
            inScript.setScriptType(SCRIPT_VOTE);

            TxIn *txIn = new TxIn();
            txIn->setNonce(activeDelegate.second.getNonce());
            txIn->setScript(inScript);
            txIn->setInAddress(activeDelegate.second.getPublicKey());

            std::vector<TxIn> txIns;
            txIns.push_back(*txIn);

            transaction->setTxIns(txIns);

            std::vector<unsigned char> signature = wallet.signWithAddress(
                    AddressHelper::addressLinkFromScript(address.getScript()),
                    TransactionHelper::getTxId(transaction)
            );

            inScript.setScript(signature);
            TxIn txInWithSignature = transaction->getTxIns().front();
            txInWithSignature.setScript(inScript);

            std::vector<TxIn> txInsWithSignature;
            txInsWithSignature.push_back(txInWithSignature);

            transaction->setTxIns(txInsWithSignature);

            Chain& chain = Chain::Instance();
            if(TransactionHelper::verifyTx(transaction, IS_IN_HEADER, chain.getBestBlockHeader())) {
                txPool.appendTransaction(*transaction);
            } else {
                success = false;
            }
        }
    }

    if(success) {
        return "{\"success\": true}";
    } else {
        return "{\"success\": false, \"error\": \"Failed to verify transaction\"}";
    }

}

std::string Api::getDelegates() {
    VoteStore& voteStore = VoteStore::Instance();
    Wallet& wallet = Wallet::Instance();
    std::map<std::vector<unsigned char>, Delegate> activeDelegates = voteStore.getActiveDelegates();
    std::map<std::vector<unsigned char>, Delegate> allDelegates = voteStore.getAllDelegates();

    std::vector<unsigned char> currentDelegateId = voteStore.getValidatorForTimestamp(Time::getCurrentTimestamp());
    ptree baseTree;
    ptree delegatesTree;
    for(auto delegate: allDelegates) {
        bool isActive = false;

        if(activeDelegates.find(delegate.first) != activeDelegates.end()) {
            isActive = true;
        }
        ptree delegateTree;
        ptree votesTree;

        delegateTree.put("pubKey", Hexdump::vectorToHexString(delegate.second.getPublicKey()));
        delegateTree.put("nonce", delegate.second.getNonce());
        delegateTree.put("totalVote", delegate.second.getTotalVote());
        delegateTree.put("votes", delegate.second.getVoteCount());
        delegateTree.put("unVotes", delegate.second.getUnVoteCount());
        delegateTree.put("lastVotedInBlock", Hexdump::vectorToHexString(delegate.second.getBlockHashLastVote()));
        delegateTree.put("isActive", isActive);
        delegateTree.put("isCurrent", currentDelegateId == delegate.first);
        delegateTree.put("isMe", wallet.isMine(
                AddressHelper::addressLinkFromScript(
                        wallet.addressFromPublicKey(delegate.second.getPublicKey()).getScript()
                )
        ));

        std::vector<Vote> votes = delegate.second.getVotes();
        for (auto vote: votes) {
            ptree voteTree;
            voteTree.put("nonce", vote.getNonce());
            voteTree.put("targetPubKey", Hexdump::vectorToHexString(vote.getTargetPubKey()));
            voteTree.put("action", vote.getAction());
            voteTree.put("fromPubKey", Hexdump::vectorToHexString(vote.getFromPubKey()));
            voteTree.put("version", vote.getVersion());
            votesTree.push_back(std::make_pair("", voteTree));
        }
        delegateTree.push_back(std::make_pair("votes", votesTree));

        delegatesTree.push_back(std::make_pair("", delegateTree));
    }

    baseTree.add_child("delegates", delegatesTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::removePeer(std::string json) {
    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    Peers &peers = Peers::Instance();

    bool removedPeer = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "ip") == 0) {
            peers.disconnect(v.second.data());
            removedPeer = true;
        }
    }

    if(removedPeer) {
        return "{\"success\": true}";
    }

    return "{\"success\": false}";
}

std::string Api::addPeer(std::string json) {
    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    Peers &peers = Peers::Instance();

    bool addPeer = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "ip") == 0) {
            auto io_service = make_shared<boost::asio::io_service>();
            tcp::resolver resolver(*io_service);

            auto work = make_shared<boost::asio::io_service::work>(*io_service);

            //@TODO check it is a ip v4 using regex
            std::string ip;
            ip = v.second.data();
            Log(LOG_LEVEL_INFO) << "ip: " << ip;
            auto endpoint_iterator = resolver.resolve({ip, NET_PORT});

            auto peer = make_shared<PeerClient>(io_service, endpoint_iterator, work);

            //std::shared_ptr<PeerClient> nPeer = peer->get();
            peer->setBlockHeight(0);
            peer->setIp(ip);
            if(peers.appendPeer(peer->get())) {
                peer->do_connect();

                auto io_service_run = [io_service]() {
                    try{
                        io_service->run();
                        //io_service->stop();
                        Log(LOG_LEVEL_INFO) << "io_service terminated";
                    }
                    catch (const std::exception& e) {
                        Log(LOG_LEVEL_ERROR) << "io_service.run terminated with: " << e.what();
                    }
                };
                std::thread t(io_service_run);
                t.detach();

                Chain& chain = Chain::Instance();

                // transmit our own block height
                TransmitBlockchainHeight *transmitBlockchainHeight = new TransmitBlockchainHeight();
                transmitBlockchainHeight->height = chain.getCurrentBlockchainHeight();
                peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(*transmitBlockchainHeight));

                //ask for blockheight
                AskForBlockchainHeight askForBlockchainHeight;
                peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForBlockchainHeight));

                //ask for donation Address
                AskForDonationAddress askForDonationAddress;
                peer->deliver(NetworkMessageHelper::serializeToNetworkMessage(askForDonationAddress));

                addPeer = true;
            } else {
                peer->close();
            }
        }
    }

    if(addPeer) {
        return "{\"success\": true}";
    }

    return "{\"success\": false}";
}

std::string Api::getPeers() {
    Peers &peers = Peers::Instance();

    std::map<std::string, PeerInterfacePtr> peerList = peers.getPeers();
    ptree baseTree;
    ptree peersTree;

    for(auto peer: peerList) {
        ptree peerTree;

        peerTree.put("ip", peer.second->getIp());
        peerTree.put("blockHeight", peer.second->getBlockHeight());
        peerTree.put("donationAddress", peer.second->getDonationAddress());

        peersTree.push_back(std::make_pair("", peerTree));
    }

    baseTree.add_child("peers", peersTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getAddress(std::vector<unsigned char> address) {
    AddressStore &addressStore = AddressStore::Instance();
    AddressForStore addressForStore = addressStore.getAddressFromStore(address);

    if(addressForStore.getScript().getScript().empty()) {
        return "{\"success\": false, \"error\": \"address not found\"}";
    }

    ptree baseTree;
    ptree addressTree;

    addressTree.put("nonce", addressForStore.getNonce());
    addressTree.put("scriptType", addressForStore.getScript().getScriptType());
    addressTree.put("script", Hexdump::vectorToHexString(addressForStore.getScript().getScript()));
    addressTree.push_back(std::make_pair("amountWithUBI", uamountToPtree(AddressHelper::getAmountWithUBI(&addressForStore))));
    addressTree.push_back(std::make_pair("amountWithoutUBI", uamountToPtree(addressForStore.getAmount())));
    addressTree.push_back(std::make_pair("UBIdebit", uamountToPtree(addressForStore.getUBIdebit())));

    auto dscToAddressLinks = addressForStore.getDscToAddressLinks();
    auto it = dscToAddressLinks.begin();
    while (it != dscToAddressLinks.end()) {
        ptree dscTree;
        dscTree.put("DscCertificate", Hexdump::vectorToHexString((*it).getDscCertificate()));
        dscTree.put("DSCLinkedAtHeight", (*it).getDSCLinkedAtHeight());
        addressTree.add_child("dsc", addressTree);
        it++;
    }

    baseTree.add_child("address", addressTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::removeBan(std::string json) {
    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    BanList& banList = BanList::Instance();

    bool removedBan = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "ip") == 0) {
            banList.removeFromBanList(v.second.data());
            removedBan = true;
        }
    }

    if(removedBan) {
        return "{\"success\": true}";
    }

    return "{\"success\": false}";
}

std::string Api::addBan(std::string json) {
    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    BanList& banList = BanList::Instance();

    bool addedBan = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "ip") == 0) {
            banList.appendBan(v.second.data(), BAN_INC_INSTA_BAN);
            addedBan = true;
        }
    }

    if(addedBan) {
        return "{\"success\": true}";
    }

    return "{\"success\": false}";
}

std::string Api::getBans() {
    BanList& banList = BanList::Instance();
    std::map<ip_t, uint16_t> bans = banList.getBanList();

    ptree baseTree;
    ptree bansTree;

    for(auto ban: bans) {
        ptree peerTree;

        peerTree.put("ip", ban.first);
        peerTree.put("score", ban.second);

        bansTree.push_back(std::make_pair("", peerTree));
    }

    baseTree.add_child("bans", bansTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::myTransactions() {
    Wallet &wallet = Wallet::Instance();
    Chain& chain = Chain::Instance();

    ptree baseTree;
    ptree transactionsTree;
    uint32_t txNbr = 0;
    auto myTransactions = wallet.getMyTransactions();
    for (std::vector<TransactionForStore>::reverse_iterator it = myTransactions.rbegin(); it != myTransactions.rend();it++) {
        ptree txInTree;
        ptree txOutTree;

        BlockHeader* header = chain.getBlockHeader(it->getBlockHash());
        // this part ensures that the transaction is on the main chain
        if(header != nullptr) {
            ptree txTree = txToPtree(it->getTx(), true);
            txTree.put("confirmations", chain.getCurrentBlockchainHeight() - header->getBlockHeight());
            transactionsTree.push_back(std::make_pair("", txTree));
            txNbr++;
            if(txNbr > MAX_NUMBER_OF_MY_TRANSACTIONS_TO_DISPLAY) {
                break;
            }
        }
    }

    baseTree.add_child("transactions", transactionsTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::readPassport(std::string json) {

    Wallet &wallet = Wallet::Instance();

    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    std::string documentNumber;
    std::string dateOfBirth;
    std::string dateOfExpiry;

    for (boost::property_tree::ptree::value_type &v : pt)
    {
        if(strcmp(v.first.data(), "documentNumber") == 0) {
            documentNumber = v.second.data();
            if(documentNumber.size() != 9) {
                return "{\"success\": false, \"error\" : \"documentNumber should be of length 9\"}";
            }
        }
        if(strcmp(v.first.data(), "dateOfBirth") == 0) {
            dateOfBirth = v.second.data();
            if(dateOfBirth.size() != 6) {
                return "{\"success\": false, \"error\" : \"dateOfBirth should be of length 6\"}";
            }
        }
        if(strcmp(v.first.data(), "dateOfExpiry") == 0) {
            dateOfExpiry = v.second.data();
            if(dateOfExpiry.size() != 6) {
                return "{\"success\": false, \"error\" : \"dateOfExpiry should be of length 6\"}";
            }
        }
    }

    BacKeys* bacKeys = new BacKeys();
    bacKeys->setDateOfBirth(dateOfBirth);
    bacKeys->setDateOfExpiry(dateOfExpiry);
    bacKeys->setDocumentNumber(documentNumber);

    SessionKeys *sessionKeys = new SessionKeys;

    Reader* reader = new Reader();
    if(reader->initConnection(bacKeys, sessionKeys))
    {
        unsigned char file[64000];
        unsigned int fileSize;
        unsigned char fileId[3] = {'\x01', '\x1D', '\0'}; // SOD

        if(!reader->readFile(fileId, file, &fileSize, sessionKeys)) {
            reader->close();
            return "{\"success\": false, \"error\" : \"failed to read SOD file\"}";
        }
        reader->close();

        Hexdump::dump(file, fileSize);

        LDSParser* ldsParser = new LDSParser(file, fileSize);

        unsigned char sod[32000];
        unsigned int sodSize = 0;

        ldsParser->getTag((unsigned char*)"\x77")
                ->getContent(sod, &sodSize);

        Hexdump::dump(sod, sodSize);

        PKCS7Parser* pkcs7Parser = new PKCS7Parser((char*)sod, sodSize);

        if(pkcs7Parser->hasError()) {
            Log() << "Pkcs7Parser has an error";
            return "{\"success\": false, \"error\" : \"Pkcs7Parser has an error\"}";
        }

        Cert* pkcsCert = new Cert();
        Address randomWalletAddress = wallet.getRandomAddressFromWallet();
        pkcsCert->setX509(pkcs7Parser->getDscCertificate());

        Transaction* registerPassportTx = new Transaction();
        TxIn* pTxIn = new TxIn();
        UScript* pIScript = new UScript();
        pIScript->setScript(std::vector<unsigned char>());
        pIScript->setScriptType(SCRIPT_REGISTER_PASSPORT);
        pTxIn->setInAddress(pkcsCert->getId());
        pTxIn->setScript(*pIScript);
        pTxIn->setNonce(0);
        pTxIn->setAmount(*(new UAmount()));
        registerPassportTx->addTxIn(*pTxIn);

        TxOut* pTxOut = new TxOut();
        pTxOut->setAmount(*(new UAmount()));
        pTxOut->setScript(randomWalletAddress.getScript());
        registerPassportTx->addTxOut(*pTxOut);
        registerPassportTx->setNetwork(NET_CURRENT);

        Log(LOG_LEVEL_INFO) << "randomWalletAddressScript : " << AddressHelper::addressLinkFromScript(randomWalletAddress.getScript());

        std::vector<unsigned char> txId = TransactionHelper::getTxId(registerPassportTx);

        if(pkcs7Parser->isRSA()) {
            NtpRskSignatureRequestObject *ntpRskSignatureRequestObject = pkcs7Parser->getNtpRsk();

            // @TODO perhaps add padding to txId
            ntpRskSignatureRequestObject->setNm(ECCtools::vectorToBn(txId));

            NtpRskSignatureVerificationObject *ntpEskSignatureVerificationObject = NtpRsk::signWithNtpRsk(
                    ntpRskSignatureRequestObject
            );

            CDataStream sntpRsk(SER_DISK, 1);
            sntpRsk << *ntpEskSignatureVerificationObject;

            Log(LOG_LEVEL_INFO) << "generated NtpRsk: " << sntpRsk;
            pIScript->setScript((unsigned char *) sntpRsk.data(), (uint16_t) sntpRsk.size());

            pTxIn->setScript(*pIScript);

        } else {

            NtpEskSignatureRequestObject *ntpEskSignatureRequestObject = pkcs7Parser->getNtpEsk();
            ntpEskSignatureRequestObject->setNewMessageHash(txId);

            Log(LOG_LEVEL_INFO) << "P-UID, Passport unique identifier (signed hash):: "
                                << ntpEskSignatureRequestObject->getMessageHash();

            std::string dscId = pkcsCert->getIdAsHexString();
            Log(LOG_LEVEL_INFO) << "dscId: " << dscId;
            Log(LOG_LEVEL_INFO) << "subject: "
                                << X509_NAME_oneline(X509_get_subject_name(pkcs7Parser->getDscCertificate()), 0, 0);


            NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = NtpEsk::signWithNtpEsk(
                    ntpEskSignatureRequestObject);

            CDataStream sntpEsk(SER_DISK, 1);
            sntpEsk << *ntpEskSignatureVerificationObject;
            Log(LOG_LEVEL_INFO) << "generated NtpEsk: " << sntpEsk;
            pIScript->setScript((unsigned char *) sntpEsk.data(), (uint16_t) sntpEsk.size());

            pTxIn->setScript(*pIScript);
        }
        std::vector<TxIn> pTxIns;
        pTxIns.push_back(*pTxIn);
        registerPassportTx->setTxIns(pTxIns);

        Chain& chain = Chain::Instance();
        if(TransactionHelper::verifyTx(registerPassportTx, IS_NOT_IN_HEADER, chain.getBestBlockHeader())) {
            Log(LOG_LEVEL_INFO) << "Passport transaction verified";
        } else {

            char pData[512];
            FS::charPathFromVectorPath(pData, FS::concatPaths(FS::getConfigBasePath(), "extractedDSC.cert"));
            FILE* fileDSC = fopen (pData , "w");

            if(fileDSC != nullptr) {
                Log(LOG_LEVEL_INFO) << "wrote to extractedDSC.cert file";
                i2d_X509_fp(fileDSC, pkcsCert->getX509());
                fclose(fileDSC);
            }

            return "{\"success\": false, \"error\" : \"couldn't verify Passport transaction\"}";
        }

        CDataStream spTx(SER_DISK, 1);
        spTx << *registerPassportTx;

        Log(LOG_LEVEL_INFO) << spTx;

        printf("register passport tx: ");
        Hexdump::dump((unsigned char*)spTx.data(), (uint16_t)spTx.size());

        TxPool& txPool = TxPool::Instance();
        if(txPool.appendTransaction(*registerPassportTx)) {
            Network &network = Network::Instance();
            network.broadCastTransaction(*registerPassportTx);
            return "{\"success\": true}";
        } else {
            return "{\"success\": false, \"error\" : \"Cannot append transaction to txPool, may be this passport is already registered\"}";
        }

    } else {
        return "{\"success\": false, \"error\" : \"couldn't read NFC chip\"}";
    }

    return "{\"success\": false}";

}

std::string Api::doKYC(std::string json) {

    Wallet &wallet = Wallet::Instance();

    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    std::string documentNumber;
    std::string dateOfBirth;
    std::string dateOfExpiry;
    std::string challenge;
    std::string type;

    for (boost::property_tree::ptree::value_type &v : pt)
    {
        if(strcmp(v.first.data(), "documentNumber") == 0) {
            documentNumber = v.second.data();
            if(documentNumber.size() != 9) {
                return "{\"success\": false, \"error\" : \"documentNumber should be of length 9\"}";
            }
        }
        if(strcmp(v.first.data(), "dateOfBirth") == 0) {
            dateOfBirth = v.second.data();
            if(dateOfBirth.size() != 6) {
                return "{\"success\": false, \"error\" : \"dateOfBirth should be of length 6\"}";
            }
        }
        if(strcmp(v.first.data(), "dateOfExpiry") == 0) {
            dateOfExpiry = v.second.data();
            if(dateOfExpiry.size() != 6) {
                return "{\"success\": false, \"error\" : \"dateOfExpiry should be of length 6\"}";
            }
        }

        if(strcmp(v.first.data(), "challenge") == 0) {
            challenge = v.second.data();
            if(challenge.size() < 1) {
                return "{\"success\": false, \"error\" : \"missing challenge\"}";
            }
        }

        if(strcmp(v.first.data(), "type") == 0) {
            type = v.second.data();
            if(type.size() < 1) {
                return "{\"success\": false, \"error\" : \"missing KYC type\"}";
            }
        }
    }

    BacKeys* bacKeys = new BacKeys();
    bacKeys->setDateOfBirth(dateOfBirth);
    bacKeys->setDateOfExpiry(dateOfExpiry);
    bacKeys->setDocumentNumber(documentNumber);

    SessionKeys *sessionKeys = new SessionKeys;

    Reader* reader = new Reader();
    if(reader->initConnection(bacKeys, sessionKeys))
    {
        unsigned char sodFile[64000];
        unsigned int sodFileSize;
        unsigned char sodFileId[3] = {'\x01', '\x1D', '\0'}; // SOD

        unsigned char dg1File[64000];
        unsigned int dg1FileSize = 0;
        unsigned char dg1FileId[3] = {'\x01', '\x01', '\0'}; // DG1

        unsigned char dg2File[64000];
        unsigned int dg2FileSize = 0;
        unsigned char dg2FileId[3] = {'\x01', '\x02', '\0'}; // DG2

        if(!reader->readFile(sodFileId, sodFile, &sodFileSize, sessionKeys)) {
            reader->close();
            return "{\"success\": false, \"error\" : \"failed to read SOD file\"}";
        }

        if(std::stoi(type) == KYC_MODE_DG1 || std::stoi(type) == KYC_MODE_DG1_AND_DG2) {
            if (!reader->readFile(dg1FileId, dg1File, &dg1FileSize, sessionKeys)) {
                reader->close();
                return "{\"success\": false, \"error\" : \"failed to read DG1 file\"}";
            }
        }

        if(std::stoi(type) == KYC_MODE_DG1_AND_DG2) {
            if (!reader->readFile(dg2FileId, dg2File, &dg2FileSize, sessionKeys)) {
                reader->close();
                return "{\"success\": false, \"error\" : \"failed to read DG2 file\"}";
            }
        }

        reader->close();

        LDSParser* ldsParser = new LDSParser(sodFile, sodFileSize);

        unsigned char sod[32000];
        unsigned int sodSize = 0;

        ldsParser->getTag((unsigned char*)"\x77")
                ->getContent(sod, &sodSize);

        Log(LOG_LEVEL_INFO) << "Sod:";
        Hexdump::dump(sod, sodSize);

        Log(LOG_LEVEL_INFO) << "DG1:";
        Hexdump::dump(dg1File, dg1FileSize);

        Log(LOG_LEVEL_INFO) << "DG2:";
        Hexdump::dump(dg2File, dg2FileSize);

        PKCS7Parser* pkcs7Parser = new PKCS7Parser((char*)sod, sodSize);

        std::vector<unsigned char> signedPayload = pkcs7Parser->getSignedPayload();
        std::vector<unsigned char> ldsPayload = pkcs7Parser->getLDSPayload();

        if(pkcs7Parser->hasError()) {
            Log() << "Pkcs7Parser has an error";
            return "{\"success\": false, \"error\" : \"Pkcs7Parser has an error\"}";
        }


        Cert* pkcsCert = new Cert();
        Address randomWalletAddress = wallet.getRandomAddressFromWallet();
        pkcsCert->setX509(pkcs7Parser->getDscCertificate());

        Transaction* registerPassportTx = new Transaction();
        TxIn* pTxIn = new TxIn();
        UScript* pIScript = new UScript();
        pIScript->setScript(std::vector<unsigned char>());
        pIScript->setScriptType(SCRIPT_REGISTER_PASSPORT);
        pTxIn->setInAddress(pkcsCert->getId());
        pTxIn->setScript(*pIScript);
        pTxIn->setNonce(0);
        pTxIn->setAmount(*(new UAmount()));
        registerPassportTx->addTxIn(*pTxIn);

        TxOut* pTxOut = new TxOut();
        pTxOut->setAmount(*(new UAmount()));
        registerPassportTx->addTxOut(*pTxOut);
        registerPassportTx->setNetwork(NET_CURRENT);

        pTxOut->setScript(randomWalletAddress.getScript());
        Log(LOG_LEVEL_INFO) << "randomWalletAddressScript : " << AddressHelper::addressLinkFromScript(randomWalletAddress.getScript());


        std::vector<unsigned char> txId = TransactionHelper::getTxId(registerPassportTx);
        std::vector<unsigned char> passportHash;

        if(pkcs7Parser->isRSA()) {
            NtpRskSignatureRequestObject *ntpRskSignatureRequestObject = pkcs7Parser->getNtpRsk();

            // @TODO perhaps add padding to txId
            ntpRskSignatureRequestObject->setNm(ECCtools::vectorToBn(txId));

            NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = NtpRsk::signWithNtpRsk(
                    ntpRskSignatureRequestObject
            );

            CDataStream sntpRsk(SER_DISK, 1);
            sntpRsk << *ntpRskSignatureVerificationObject;

            Log(LOG_LEVEL_INFO) << "generated NtpRsk: " << sntpRsk;
            pIScript->setScript((unsigned char *) sntpRsk.data(), (uint16_t) sntpRsk.size());

            passportHash = ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM());

        } else {

            NtpEskSignatureRequestObject *ntpEskSignatureRequestObject = pkcs7Parser->getNtpEsk();
            ntpEskSignatureRequestObject->setNewMessageHash(txId);

            Log(LOG_LEVEL_INFO) << "P-UID, Passport unique identifier (signed hash):: "
                                << ntpEskSignatureRequestObject->getMessageHash();

            std::string dscId = pkcsCert->getIdAsHexString();
            Log(LOG_LEVEL_INFO) << "dscId: " << dscId;
            Log(LOG_LEVEL_INFO) << "subject: "
                                << X509_NAME_oneline(X509_get_subject_name(pkcs7Parser->getDscCertificate()), 0, 0);

            NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = NtpEsk::signWithNtpEsk(ntpEskSignatureRequestObject);

            CDataStream sntpEsk(SER_DISK, 1);
            sntpEsk << *ntpEskSignatureVerificationObject;
            Log(LOG_LEVEL_INFO) << "generated NtpEsk: " << sntpEsk;
            pIScript->setScript((unsigned char *) sntpEsk.data(), (uint16_t) sntpEsk.size());

            passportHash = ntpEskSignatureVerificationObject->getMessageHash();
        }

        std::vector<unsigned char> challengeSignature;
        std::vector<unsigned char> challengeVector = std::vector<unsigned char>(challenge.c_str(), challenge.c_str() + challenge.size());

        // verify if passport already exists on the blockchain
        DB& db = DB::Instance();

        KycRequestScript kycRequestScript;

        auto ntpskEntry = db.getFromDB(DB_NTPSK_ALREADY_USED, passportHash);
        if(ntpskEntry.empty()) {  // if it doesn't exist we include the verification payload
            pTxIn->setScript(*pIScript);
            challengeSignature = wallet.signWithAddress(AddressHelper::addressLinkFromScript(randomWalletAddress.getScript()), challengeVector);
            kycRequestScript.setTransaction(*registerPassportTx);
            kycRequestScript.setPublicKey(wallet.getPublicKeyFromAddressLink(registerPassportTx->getTxOuts().front().getScript().getScript()));
        } else {

            CDataStream ntpskEntryScript(SER_DISK, 1);
            ntpskEntryScript.write((char *) ntpskEntry.data(), ntpskEntry.size());

            NtpskAlreadyUsedScript ntpskAlreadyUsedScript;
            ntpskEntryScript >> ntpskAlreadyUsedScript;

            UScript script;
            script.setScript(ntpskAlreadyUsedScript.getAddress());
            script.setScriptType(SCRIPT_PKH);
            challengeSignature = wallet.signWithAddress(AddressHelper::addressLinkFromScript(script), challengeVector);
            kycRequestScript.setPassportHash(passportHash);
            kycRequestScript.setPublicKey(wallet.getPublicKeyFromAddressLink(AddressHelper::addressLinkFromScript(script)));
        }

        std::vector<TxIn> pTxIns;
        pTxIns.push_back(*pTxIn);
        registerPassportTx->setTxIns(pTxIns);

        std::vector<unsigned char> dg1Vector = std::vector<unsigned char>(dg1File, dg1File + dg1FileSize);
        std::vector<unsigned char> dg2Vector = std::vector<unsigned char>(dg2File, dg2File + dg2FileSize);

        kycRequestScript.setChallenge(challengeVector);
        kycRequestScript.setChallengeSignature(challengeSignature);
        kycRequestScript.setDg1(dg1Vector);
        kycRequestScript.setDg2(dg2Vector);
        kycRequestScript.setMode((uint8_t) stoi(type.c_str()));
        kycRequestScript.setSignedPayload(signedPayload);
        kycRequestScript.setLdsPayload(ldsPayload);
        kycRequestScript.setMdAlg((uint16_t)pkcs7Parser->getMdAlg());

        CDataStream krs(SER_DISK, 1);
        krs << kycRequestScript;

        std::string krs64 = base64_encode((unsigned char*)krs.str().data(), (uint32_t)krs.str().size());

        ptree baseTree;

        baseTree.put("success", true);
        baseTree.put("base64", krs64);

        std::stringstream ss2;
        boost::property_tree::json_parser::write_json(ss2, baseTree);

        return ss2.str();

    } else {
        return "{\"success\": false, \"error\" : \"couldn't read NFC chip\"}";
    }

    return "{\"success\": false}";

}

std::string Api::pay(std::string json) {

    Wallet &wallet = Wallet::Instance();

    if (json.empty()) {
        return "{\"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    std::vector<TxOut> txOuts;

    for (boost::property_tree::ptree::value_type &v : pt) {
        TxOut txOut;
        if(!wallet.verifyReadableAddressChecksum(v.first.data())) {
            return "{\"error\": \"invalid address\"}";
        }
        std::vector<unsigned char> vectorAddress = wallet.readableAddressToVectorAddress(v.first.data());
        Address address;
        CDataStream s(SER_DISK, 1);
        s.write((char *) vectorAddress.data(), vectorAddress.size());
        s >> address;

        txOut.setScript(address.getScript());

        std::cout << v.first.data() << std::endl;
        UAmount uAmountAggregated;
        for (boost::property_tree::ptree::value_type &v2 : v.second) {
            std::cout << v2.first.data() << std::endl;
            std::cout << v2.second.get_value<uint64_t>() << std::endl;

            UAmount uAmount;
            uAmount.map.insert(std::make_pair((uint8_t) atoi(v2.first.data()), v2.second.get_value<uint64_t>()));
            uAmountAggregated += uAmount;
        }
        txOut.setAmount(uAmountAggregated);
        txOuts.push_back(txOut);
    }

    Transaction *tx = wallet.payToTxOutputs(txOuts);

    if (tx == nullptr) {
        return "{\"success\": false}";
    }

    TxPool &txPool = TxPool::Instance();
    if (txPool.appendTransaction(*tx)) {

        Network &network = Network::Instance();
        network.broadCastTransaction(*tx);

        return "{\"success\": true}";
    }

    return "{\"success\": false}";
}

std::string Api::verifyKYC(std::string json) {

    if (json.empty()) {
        return "{\"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "base64") == 0) {
            CDataStream s(SER_DISK, 1);
            std::string b64String = base64_decode(v.second.data());
            s.write(b64String.c_str(), b64String.length());

            KycRequestScript krs;
            try {
                s >> krs;
            } catch (const std::exception& e) {
                Log(LOG_LEVEL_ERROR) << "Cannot deserialize base64 encoded kyc request";
                Log(LOG_LEVEL_ERROR) << e.what();
                Log(LOG_LEVEL_ERROR) << Hexdump::ucharToHexString((unsigned char*)b64String.c_str(), b64String.length());
                return "{\"success\": false, \"error\":\"Cannot deserialize base64 encoded kyc request\"}";
            }

            Log(LOG_LEVEL_INFO) << "DG1:" << krs.getDg1();
            Log(LOG_LEVEL_INFO) << "LDS payload:" << krs.getLdsPayload();
            LDSParser* ldsParserDG1 = new LDSParser(krs.getDg1());
            LDSParser* tag61 = ldsParserDG1->getTag((unsigned char *) "\x61");
            if (tag61 == nullptr) return "{\"success\": false, \"error\":\"tag61 == nullptr\"}";
            LDSParser* tag5F1F = tag61->getTag((unsigned char *) "\x5F\x1F");
            if (tag5F1F == nullptr) return "{\"success\": false, \"error\":\"tag5F1F == nullptr\"}";

            std::vector<unsigned char> mrz = tag5F1F->getContent();

            Log(LOG_LEVEL_INFO) << "DG2: " << krs.getDg2();

            std::vector<unsigned char> passportHash = krs.getPassportHash();
            Transaction tx = krs.getTransaction();
            CertStore &certStore = CertStore::Instance();
            Cert *cert;
            std::vector<unsigned char> currentAddress;

            if(passportHash.empty()) {
                if (!TransactionHelper::isRegisterPassport(&tx)) {
                    return "{\"success\": false, \"error\":\"Transaction is not of type register passport\"}";
                }

                std::vector<unsigned char> txId = TransactionHelper::getTxId(&tx);
                TxIn txIn = tx.getTxIns().front();
                UScript script = txIn.getScript();

                CDataStream srpScript(SER_DISK, 1);
                srpScript.write((char *) script.getScript().data(), script.getScript().size());

                cert = certStore.getDscCertWithCertId(txIn.getInAddress());
                if (cert == nullptr) return "{\"success\": false, \"error\":\"cert == nullptr\"}";

                if ((uint32_t) script.getScript().at(0) % 2 == 0) {
                    // is NtpRsk
                    NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();

                    try {
                        srpScript >> *ntpRskSignatureVerificationObject;
                    } catch (const std::exception &e) {
                        Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";

                        return "{\"success\": false, \"error\":\"Failed to deserialize SCRIPT_REGISTER_PASSPORT payload\"}";
                    }

                    passportHash = ECCtools::bnToVector(ntpRskSignatureVerificationObject->getM());

                } else {
                    // is NtpEsk
                    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(cert->getPubKey());
                    NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject = new NtpEskSignatureVerificationObject();
                    ntpEskSignatureVerificationObject->setPubKey(EC_KEY_get0_public_key(ecKey));
                    ntpEskSignatureVerificationObject->setCurveParams(EC_KEY_get0_group(ecKey));
                    ntpEskSignatureVerificationObject->setNewMessageHash(txId);

                    try {
                        srpScript >> *ntpEskSignatureVerificationObject;
                    } catch (const std::exception &e) {
                        Log(LOG_LEVEL_ERROR) << "Failed to deserialize SCRIPT_REGISTER_PASSPORT payload";
                        return "{\"success\": false, \"error\":\"Failed to deserialize SCRIPT_REGISTER_PASSPORT payload\"}";
                    }

                    passportHash = ntpEskSignatureVerificationObject->getMessageHash();
                }

                if(!TransactionHelper::verifyRegisterPassportTx(&tx)) {
                    return "{\"success\": false, \"error\":\"Cannot verify kyc transaction\"}";
                }

                currentAddress = tx.getTxOuts().front().getScript().getScript();

            } else {

                // verify if passport already exists on the blockchain
                DB& db = DB::Instance();

                auto ntpEskEntry = db.getFromDB(DB_NTPSK_ALREADY_USED, passportHash);
                if(!ntpEskEntry.empty()) {
                    CDataStream neScript(SER_DISK, 1);
                    neScript.write((char *) ntpEskEntry.data(), ntpEskEntry.size());
                    NtpskAlreadyUsedScript ntpskAlreadyUsedScript;
                    neScript >> ntpskAlreadyUsedScript;

                    cert = certStore.getDscCertWithCertId(ntpskAlreadyUsedScript.getDscID());
                    currentAddress = ntpskAlreadyUsedScript.getAddress();

                    Address recoveredAddress = Wallet::addressFromPublicKey(
                            krs.getPublicKey()
                    );

                    if(currentAddress != recoveredAddress.getScript().getScript()) {
                        Log(LOG_LEVEL_ERROR) << "current register passport transaction address and the one on the blockchain mismatch";

                        return "{\"success\": false, \"error\":\"current register passport transaction address and the one on the blockchain mismatch\"}";
                    }
                } else {
                    return "{\"success\": false, \"error\":\"unknown passport hash\"}";
                }
            }


            // verify challenge signature
            if(!VerifySignature::verify(krs.getChallenge(), krs.getChallengeSignature(), krs.getPublicKey())) {
                return "{\"success\": false, \"error\":\"Challenge signature verification failed\"}";
            }

            Address recoveredAddress = Wallet::addressFromPublicKey(
                    krs.getPublicKey()
            );

            if(recoveredAddress.getScript().getScript() != currentAddress) {
                return "{\"success\": false, \"error\":\"Public key doesn't match transaction address\"}";
            }

            bool dg1HashMatch = false, dg2HashMatch = false;
            if(krs.getMode() != KYC_MODE_ANONYMOUS) {
                // Step 1 verify signed hash
                LDSParser *ldsParser0 = new LDSParser(krs.getSignedPayload());
                std::vector<LDSParser> sequence0 = ldsParser0->getSequence();

                if (sequence0.size() < 2) return "{\"success\": false, \"error\":\"sequence0.size() < 2\"}";
                std::vector<LDSParser> sequence01 = sequence0.at(1).getSequence();

                if (sequence01.size() < 2) return "{\"success\": false, \"error\":\"sequence01.size() < 2\"}";
                std::vector<LDSParser> sequence02 = sequence01.at(1).getSequence();
                if (sequence02.size() < 1) return "{\"success\": false, \"error\":\"sequence02.size() < 1\"}";

                LDSParser *tag04 = sequence02.at(0).getTag((unsigned char *) "\x04");
                if (tag04 == nullptr) return "{\"success\": false, \"error\":\"tag04 == nullptr\"}";

                unsigned char digest[128];
                unsigned int digestLength;
                EVP_MD_CTX *mdctx;
                mdctx = EVP_MD_CTX_create();

                EVP_DigestInit_ex(mdctx, EVP_get_digestbynid(krs.getMdAlg()), NULL);
                EVP_DigestUpdate(mdctx, krs.getSignedPayload().data(), krs.getSignedPayload().size());
                EVP_DigestFinal_ex(mdctx, digest, &digestLength);

                EVP_MD_CTX_destroy(mdctx);

                if (memcmp(digest, passportHash.data(), digestLength) != 0) {
                    Log(LOG_LEVEL_ERROR) << "Signed payload hash mismatch";

                    return "{\"success\": false, \"error\":\"Signed payload hash mismatch\"}";
                }

                // Step 2 verify the payload
                LDSParser *ldsParser = new LDSParser(krs.getLdsPayload());

                std::vector<LDSParser> sequence1 = ldsParser->getSequence();

                if (sequence1.size() < 2) return "{\"success\": false, \"error\":\"sequence1.size() < 2\"}";

                LDSParser algoLDS = sequence1.at(1);
                std::vector<LDSParser> algoSequence = algoLDS.getSequence();
                if (algoSequence.size() < 2) return "{\"success\": false, \"error\":\"algoSequence.size() < 2\"}";

                unsigned char *content = (unsigned char *) malloc(120);
                unsigned int contentLength = 0;
                algoSequence.at(0).getContent(content, &contentLength);
                ASN1_OBJECT *o = d2i_ASN1_OBJECT(nullptr, (const unsigned char **) &content, contentLength);
                int nid = OBJ_obj2nid(o);
                const EVP_MD *digestAlgo = EVP_get_digestbynid(nid);

                LDSParser hashListLDS = sequence1.at(2);

                Log(LOG_LEVEL_INFO) << "hashListLDS: " << hashListLDS.getContent();

                std::vector<LDSParser> hashListSequence = hashListLDS.getSequence();

                Log(LOG_LEVEL_INFO) << "hashListLDS size: " << (uint64_t) hashListSequence.size();

                unsigned char digestDG1[128];
                unsigned int digestDG1Length;

                EVP_MD_CTX *mdctx2;
                mdctx2 = EVP_MD_CTX_create();

                EVP_DigestInit_ex(mdctx2, digestAlgo, NULL);
                EVP_DigestUpdate(mdctx2, krs.getDg1().data(), krs.getDg1().size());
                EVP_DigestFinal_ex(mdctx2, digestDG1, &digestDG1Length);

                EVP_MD_CTX_destroy(mdctx2);

                unsigned char digestDG2[128];
                unsigned int digestDG2Length;

                EVP_MD_CTX *mdctx3;
                mdctx3 = EVP_MD_CTX_create();

                EVP_DigestInit_ex(mdctx3, digestAlgo, NULL);
                EVP_DigestUpdate(mdctx3, krs.getDg2().data(), krs.getDg2().size());
                EVP_DigestFinal_ex(mdctx3, digestDG2, &digestDG2Length);

                EVP_MD_CTX_destroy(mdctx3);

                for(int i=0; i < hashListSequence.size(); i++) {
                    std::vector<LDSParser> innerSeq = hashListSequence.at((unsigned long)i).getSequence();

                    if(innerSeq.size() < 2) { return "{\"success\": false, \"error\": \"innerSeq.size() < 2\"}"; }

                    LDSParser* tag04 = innerSeq.at(1).getTag((unsigned char*)"\x04");

                    if(tag04 == nullptr) { return "{\"success\": false, \"error\": \"tag04 == nullptr\"}"; }

                    if(memcmp(tag04->getContent().data(), digestDG1, digestDG1Length) == 0) {
                        dg1HashMatch = true;
                    }

                    if(memcmp(tag04->getContent().data(), digestDG2, digestDG2Length) == 0) {
                        dg2HashMatch = true;
                    }
                }

            }

            auto challenge = krs.getChallenge();

            ptree baseTree;
            baseTree.put("success", true);
            baseTree.put("dscID", Hexdump::vectorToHexString(cert->getId()));
            baseTree.put("currencyID", cert->getCurrencyId());
            baseTree.put("expiration", cert->getExpirationDate());
            baseTree.put("passportHash", Hexdump::vectorToHexString(passportHash));
            baseTree.put("challenge", std::string(challenge.data(), challenge.data() + challenge.size()));

            if(dg1HashMatch) {
                MRZParser mrzParser;
                MRZResponseObject mrzResponseObject = mrzParser.parse(mrz);
                baseTree.put("passportNumber", mrzResponseObject.getPassportNumber());
                baseTree.put("name", mrzResponseObject.getName());
                baseTree.put("isoCountryCode", mrzResponseObject.getIso2CountryCode());
                baseTree.put("gender", mrzResponseObject.getGender());
                baseTree.put("dateOfExpiry", mrzResponseObject.getDateOfExpiry());
                baseTree.put("dateOfBirth", mrzResponseObject.getDateOfBirth());
                baseTree.put("mrz", std::string(mrz.data(), mrz.data() + mrz.size()));
            }

            if(dg2HashMatch) {
                LDSParser* dg2LDS = new LDSParser(krs.getDg2());
                LDSParser* tag75 = dg2LDS->getTag((unsigned char*)"\x75");
                if(tag75 == nullptr) { return "{\"success\": false, \"error\": \"tag75 == nullptr\"}"; }

                LDSParser* tag7F61 = tag75->getTag((unsigned char*)"\x7F\x61");
                if(tag7F61 == nullptr) { return "{\"success\": false, \"error\": \"tag7F61 == nullptr\"}"; }

                LDSParser* tag7F60 = tag7F61->getTag((unsigned char*)"\x7F\x60");
                if(tag7F60 == nullptr) { return "{\"success\": false, \"error\": \"tag7F60 == nullptr\"}"; }

                std::vector<unsigned char> iso19794Bytes;

                if(tag7F60->getTag((unsigned char*)"\x7F\x2E") != nullptr) {
                    iso19794Bytes = tag7F60->getTag((unsigned char*)"\x7F\x2E")->getContent();
                } else if(tag7F60->getTag((unsigned char*)"\x5F\x2E") != nullptr) {
                    iso19794Bytes = tag7F60->getTag((unsigned char*)"\x5F\x2E")->getContent();
                }

                Iso19794Parser* iso19794Parser = new Iso19794Parser(iso19794Bytes);
                auto image = iso19794Parser->getImage();
                baseTree.put("facialImage", base64_encode(image.data(), image.size()));
            }
            std::stringstream ss;
            boost::property_tree::json_parser::write_json(ss, baseTree);

            switch(krs.getMode()) {

                case KYC_MODE_ANONYMOUS: {
                    return ss.str();
                }
                case KYC_MODE_DG1: {
                    if(!dg1HashMatch) {
                        return "{\"success\": false, \"error\": \"!dg1HashMatch\"}";
                    }

                    return ss.str();
                }
                case KYC_MODE_DG1_AND_DG2: {
                    if(!dg1HashMatch || !dg2HashMatch) {
                        return "{\"success\": false, \"error\": \"!dg1HashMatch || !dg2HashMatch\"}";
                    }

                    return ss.str();
                }
            }

            return "{\"success\": false, \"error\": \"invalid mode\"}";

        }
    }
    return "{\"success\": false, \"error\": \"missing base64 parameter\"}";
}

std::string Api::createTransaction(std::string json) {
    Wallet &wallet = Wallet::Instance();

    if (json.empty()) {
        return "{\"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    std::vector<TxOut> txOuts;

    for (boost::property_tree::ptree::value_type &v : pt) {
        TxOut txOut;
        if(!wallet.verifyReadableAddressChecksum(v.first.data())) {
            return "{\"error\": \"invalid address\"}";
        }
        std::vector<unsigned char> vectorAddress = wallet.readableAddressToVectorAddress(v.first.data());
        Address address;
        CDataStream s(SER_DISK, 1);
        s.write((char *) vectorAddress.data(), vectorAddress.size());
        s >> address;

        txOut.setScript(address.getScript());

        std::cout << v.first.data() << std::endl;
        UAmount uAmountAggregated;
        for (boost::property_tree::ptree::value_type &v2 : v.second) {
            std::cout << v2.first.data() << std::endl;
            std::cout << v2.second.get_value<uint64_t>() << std::endl;

            UAmount uAmount;
            uAmount.map.insert(std::make_pair((uint8_t) atoi(v2.first.data()), v2.second.get_value<uint64_t>()));
            uAmountAggregated += uAmount;
        }
        txOut.setAmount(uAmountAggregated);
        txOuts.push_back(txOut);
    }

    Transaction *tx = wallet.payToTxOutputs(txOuts);

    CDataStream s2(SER_DISK, 1);
    if (tx == nullptr) {
        return "{\"success\": false}";
    }

    s2 << *tx;
    std::string tx64 = base64_encode((unsigned char*)s2.str().data(), (uint32_t)s2.str().size());
    ptree baseTree;

    baseTree.put("success", true);
    baseTree.push_back(std::make_pair("transaction", txToPtree(*tx, false)));
    baseTree.put("base64", tx64);

    std::stringstream ss2;
    boost::property_tree::json_parser::write_json(ss2, baseTree);

    return ss2.str();
}

std::string Api::sendTransaction(std::string json) {
    Wallet &wallet = Wallet::Instance();

    if (json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);

    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "base64") == 0) {
            CDataStream s(SER_DISK, 1);
            std::string txString = base64_decode(v.second.data());
            s.write(txString.c_str(), txString.length());

            Transaction tx;
            try {
                s >> tx;
            } catch (const std::exception& e) {
                Log(LOG_LEVEL_ERROR) << "Cannot deserialize base64 encoded transaction";
                return "{\"success\": false, \"error\":\"Cannot deserialize base64 encoded transaction\"}";
            }

            TxPool &txPool = TxPool::Instance();
            if (txPool.appendTransaction(tx)) {

                Network &network = Network::Instance();
                network.broadCastTransaction(tx);

                return "{\"success\": true}";
            } else {
                return "{\"success\": false}";
            }
        }
    }
    return "{\"success\": false, \"error\": \"missing base64 parameter\"}";
}

void startMintingThread() {
    Mint& mint = Mint::Instance();
    mint.startMinting();
}

std::string Api::startMint() {
    std::thread t1(&startMintingThread);
    t1.detach();
    return "{\"done\": true}";
}

std::string Api::stopMint() {
    Mint& mint = Mint::Instance();
    mint.stopMinting();
    return "{\"done\": true}";
}

std::string Api::mintStatus() {
    Mint& mint = Mint::Instance();
    if(mint.getStatus()) {
        return "{\"minting\": true}";
    }
    return "{\"minting\": false}";
}

std::string Api::getUbi() {
    Wallet &wallet = Wallet::Instance();

    ptree baseTree;
    ptree ubisTree;
    for(std::vector<unsigned char> addressScript: wallet.getAddressesScript()) {
        ptree ubiTree;
        UScript addressUScript;
        addressUScript.setScript(addressScript);
        addressUScript.setScriptType(SCRIPT_PKH);

        std::vector<unsigned char> addressLink = AddressHelper::addressLinkFromScript(addressUScript);

        AddressStore &addressStore = AddressStore::Instance();
        AddressForStore addressForStore = addressStore.getAddressFromStore(addressLink);

        if(UBICalculator::isAddressConnectedToADSC(&addressForStore)) {

            auto dscToAddressLinks = addressForStore.getDscToAddressLinks();
            auto it = dscToAddressLinks.begin();
            while (it != dscToAddressLinks.end()) {
                ptree dscTree;
                dscTree.put("DscCertificate", Hexdump::vectorToHexString((*it).getDscCertificate()));
                dscTree.put("DSCLinkedAtHeight", (*it).getDSCLinkedAtHeight());
                ubiTree.add_child("dsc", dscTree);
                it++;
            }

            UAmount received = UBICalculator::totalReceivedUBI(&addressForStore);
            ubiTree.push_back(std::make_pair("totalUbiReceived", uamountToPtree(received)));

            ubisTree.push_back(std::make_pair("", ubiTree));
        }
    }

    baseTree.push_back(std::make_pair("ubis", ubisTree));
    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getWallet() {
    Wallet &wallet = Wallet::Instance();

    ptree baseTree;
    ptree addressesTree;
    UAmount balance;
    for(std::vector<unsigned char> addressScript: wallet.getAddressesScript()) {
        ptree addressTree;
        UScript addressUScript;
        addressUScript.setScript(addressScript);
        addressUScript.setScriptType(SCRIPT_PKH);

        std::vector<unsigned char> addressLink = AddressHelper::addressLinkFromScript(addressUScript);

        //Log(LOG_LEVEL_INFO) << "Wallet lookup for " << addressLink;
        AddressStore &addressStore = AddressStore::Instance();
        AddressForStore addressForStore = addressStore.getAddressFromStore(addressLink);

        UAmount addressBalance = AddressHelper::getAmountWithUBI(&addressForStore);
        balance += addressBalance;

        Address* address = new Address();
        address->setScript(addressUScript);

        addressTree.put("readable", Wallet::readableAddressFromAddress(*address));
        addressTree.put("addressLink", Hexdump::vectorToHexString(addressLink));
        addressTree.put("hexscript", Hexdump::vectorToHexString(addressScript));
        addressTree.put("pubKey", Hexdump::vectorToHexString(wallet.getPublicKeyFromAddressLink(addressLink)));
        addressTree.push_back(std::make_pair("amount", uamountToPtree(addressBalance)));
        addressesTree.push_back(std::make_pair("", addressTree));

        if(addressBalance > 0) {
            Log(LOG_LEVEL_INFO) << "addressBalance: " << addressBalance;
        }
    }

    baseTree.push_back(std::make_pair("addresses", addressesTree));
    baseTree.push_back(std::make_pair("total", uamountToPtree(balance)));

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getTxPool() {
    TxPool &txPool = TxPool::Instance();

    ptree baseTree;
    ptree transactionsTree;
    for(auto transaction: txPool.getTransactionList()) {
        transactionsTree.push_back(std::make_pair("", txToPtree(transaction.second, true)));
    }

    baseTree.add_child("transactions", transactionsTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}


std::string Api::getFees() {
    Chain& chain = Chain::Instance();

    UAmount feeFor1000bytes = TransactionHelper::calculateMinimumFee(1000, chain.getBestBlockHeader());

    ptree baseTree;
    baseTree.put("description", "Fees for 1MB (1000 bytes)");
    baseTree.push_back(std::make_pair("fees", uamountToPtree(feeFor1000bytes)));

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getIncomingTx() {
    TxPool &txPool = TxPool::Instance();
    Wallet& wallet = Wallet::Instance();

    ptree baseTree;
    ptree transactionsTree;
    for(auto transaction: txPool.getTransactionList()) {
        for(auto txOut : transaction.second.getTxOuts()) {
            if(wallet.isMine(txOut.getScript())) {
                transactionsTree.push_back(std::make_pair("", txToPtree(transaction.second, true)));
                break;
            }
        }
    }

    baseTree.add_child("transactions", transactionsTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getBlock(uint32_t blockHeight) {
    Chain& chain = Chain::Instance();
    BlockHeader* blockHeader = chain.getBlockHeader(blockHeight);

    if(blockHeader != nullptr) {
        return Api::getBlock(blockHeader->getHeaderHash());
    }

    return "{\"error\": \"Block not found\"}";
}

std::string Api::getBlock(std::vector<unsigned char> blockHeaderHash) {

    Chain& chain = Chain::Instance();
    BlockHeader* blockHeader = chain.getBlockHeader(blockHeaderHash);

    if(blockHeader == NULL) {
        Log(LOG_LEVEL_WARNING) << "BlockHeader with hash " << blockHeaderHash << "was not found";

        std::stringstream ss;
        boost::property_tree::json_parser::write_json(ss, error("Block not found!"));

        return ss.str();
    }

    ptree baseTree;
    ptree blockHeaderTree;
    ptree transactionsTree;

    blockHeaderTree.put("headerHash", Hexdump::vectorToHexString(blockHeaderHash));
    blockHeaderTree.put("previousHeaderHash", Hexdump::vectorToHexString(blockHeader->getPreviousHeaderHash()));
    blockHeaderTree.put("merkleRootHash", Hexdump::vectorToHexString(blockHeader->getMerkleRootHash()));
    blockHeaderTree.put("blockHeight", blockHeader->getBlockHeight());
    blockHeaderTree.put("timestamp", blockHeader->getTimestamp());
    blockHeaderTree.put("issuerPubKey", Hexdump::vectorToHexString(blockHeader->getIssuerPubKey()));
    blockHeaderTree.put("issuerSignature", Hexdump::vectorToHexString(blockHeader->getIssuerSignature()));
    blockHeaderTree.push_back(std::make_pair("payout", uamountToPtree(blockHeader->getPayout())));
    blockHeaderTree.push_back(std::make_pair("payoutRemainder", uamountToPtree(blockHeader->getPayoutRemainder())));
    blockHeaderTree.push_back(std::make_pair("ubiReceiverCount", uamountToPtree(blockHeader->getUbiReceiverCount())));
    ptree votesTree;
    for(auto vote: blockHeader->getVotes()) {
        votesTree.push_back(std::make_pair("", txToPtree(vote, false)));
    }
    blockHeaderTree.push_back(std::make_pair("votes", votesTree));

    baseTree.add_child("blockHeader", blockHeaderTree);

    Block* block = BlockStore::getBlock(blockHeaderHash);

    std::vector<Transaction> transactionList = block->getTransactions();

    for(auto transaction: transactionList) {
        transactionsTree.push_back(std::make_pair("", txToPtree(transaction, false)));
    }

    baseTree.add_child("transactions", transactionsTree);

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getIndex() {
    Chain& chain = Chain::Instance();
    Network& network = Network::Instance();
    Peers& peers = Peers::Instance();

    ptree baseTree;
    ptree bestBlock;

    BlockHeader* header = chain.getBestBlockHeader();
    if(header == nullptr) {
        bestBlock.put("hash", "(none)");
    } else {
        bestBlock.put("hash", Hexdump::vectorToHexString(chain.getBestBlockHeader()->getHeaderHash()));
    }
    bestBlock.put("height", chain.getCurrentBlockchainHeight());

    baseTree.add_child("bestBlock", bestBlock);
    baseTree.put("synced", network.synced);
    baseTree.put("peersCount", peers.getPeers().size());

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getRootCertificates() {
    CertStore& certStore = CertStore::Instance();

    ptree baseTree;

    std::map<std::vector<unsigned char>, Cert> rootList = certStore.getRootList();

    for(std::map<std::vector<unsigned char>, Cert>::iterator it = rootList.begin(); it != rootList.end(); it++) {
        ptree cert;
        cert.put("active", it->second.isCertAtive());
        cert.put("currency", it->second.getCurrencyId());
        cert.put("expirationDate", it->second.getExpirationDate());
        baseTree.add_child(Hexdump::vectorToHexString(it->first), cert);
    }

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getCSCACertificates() {
    CertStore& certStore = CertStore::Instance();

    ptree baseTree;

    std::map<std::vector<unsigned char>, Cert>* cscaList = certStore.getCSCAList();

    for(std::map<std::vector<unsigned char>, Cert>::iterator it = cscaList->begin(); it != cscaList->end(); it++) {
        ptree cert;
        cert.put("active", it->second.isCertAtive());
        cert.put("currency", it->second.getCurrencyId());
        cert.put("expirationDate", it->second.getExpirationDate());
        cert.put("rootSignature", Hexdump::vectorToHexString(it->second.getRootSignature()));
        baseTree.add_child(Hexdump::vectorToHexString(it->first), cert);
    }

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}

std::string Api::getDSCCertificate(std::string dscIdString) {
    CertStore& certStore = CertStore::Instance();

    Cert* dsc = certStore.getDscCertWithCertId(Hexdump::hexStringToVector(dscIdString));
    if(dsc == nullptr) {
        return "{\"error\": \"DSC not found\"}";
    }

    ptree cert;
    cert.push_back(std::make_pair("statusList", statusListToPtree(dsc->getStatusList())));
    cert.put("active", dsc->isCertAtive());
    cert.put("currency", dsc->getCurrencyId());
    cert.put("expirationDate", dsc->getExpirationDate());
    cert.put("rootSignature", Hexdump::vectorToHexString(dsc->getRootSignature()));

    BIO *mem = BIO_new(BIO_s_mem());
    X509_print(mem, dsc->getX509());
    char* x509Buffer;
    BIO_get_mem_data(mem, &x509Buffer);

    BIO_set_close(mem, BIO_CLOSE);
    BIO_free(mem);

    cert.put("x509", (std::string)(x509Buffer));

    X509_NAME *name = X509_get_issuer_name(dsc->getX509());

    char* charName = X509_NAME_oneline(name, NULL, 0);
    cert.put("issuer", (std::string)(charName));

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, cert);

    return ss.str();
}


std::string Api::getCSCACertificate(std::string cscaIdString) {
    CertStore& certStore = CertStore::Instance();

    Cert* csca = certStore.getCscaCertWithCertId(Hexdump::hexStringToVector(cscaIdString));
    if(csca == nullptr) {
        return "{\"error\": \"CSCA not found\"}";
    }

    ptree cert;
    cert.push_back(std::make_pair("statusList", statusListToPtree(csca->getStatusList())));
    cert.put("active", csca->isCertAtive());
    cert.put("currency", csca->getCurrencyId());
    cert.put("expirationDate", csca->getExpirationDate());
    cert.put("rootSignature", Hexdump::vectorToHexString(csca->getRootSignature()));

    BIO *mem = BIO_new(BIO_s_mem());
    X509_print(mem, csca->getX509());
    char* x509Buffer;
    BIO_get_mem_data(mem, &x509Buffer);

    BIO_set_close(mem, BIO_CLOSE);
    BIO_free(mem);

    cert.put("x509", (std::string)(x509Buffer));

    X509_NAME *name = X509_get_issuer_name(csca->getX509());

    char* charName = X509_NAME_oneline(name, NULL, 0);
    cert.put("issuer", (std::string)(charName));

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, cert);

    return ss.str();
}

std::string Api::getDSCCertificates() {
    CertStore& certStore = CertStore::Instance();

    ptree baseTree;

    std::unordered_map<std::string, Cert>* dscList = certStore.getDSCList();

    for(std::unordered_map<std::string, Cert>::iterator it = dscList->begin(); it != dscList->end(); it++) {
        ptree cert;
        cert.push_back(std::make_pair("statusList", statusListToPtree(it->second.getStatusList())));
        cert.put("active", it->second.isCertAtive());
        cert.put("currency", it->second.getCurrencyId());
        cert.put("expirationDate", it->second.getExpirationDate());
        cert.put("rootSignature", Hexdump::vectorToHexString(it->second.getRootSignature()));
        baseTree.add_child(it->first, cert);
    }

    std::stringstream ss;
    boost::property_tree::json_parser::write_json(ss, baseTree);

    return ss.str();
}


std::string Api::addCert(std::string json, uint8_t type) {

    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    // @TODO

    return "{\"success\": false}";
}


std::string Api::removeCert(std::string json, uint8_t type) {

    if(json.empty()) {
        return "{\"success\": false, \"error\": \"empty json\"}";
    }

    std::stringstream ss(json);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    Peers &peers = Peers::Instance();

    bool removedPeer = false;
    for (boost::property_tree::ptree::value_type &v : pt) {
        if (strcmp(v.first.data(), "certId") == 0) {
            std::vector<unsigned char> certId = Hexdump::hexStringToVector(v.second.data());
            CertStore& certStore = CertStore::Instance();
            Cert* cert;
            switch(type) {
                case TYPE_DSC:
                    cert = certStore.getDscCertWithCertId(certId);
                    break;
                case TYPE_CSCA:
                    cert = certStore.getCscaCertWithCertId(certId);
                    break;
                default:
                    Log(LOG_LEVEL_ERROR) << "Unknown cert type:" << type;
                    return "{\"success\": false, \"error\": \"Unknown cert typen\"}";
            }

            if(cert == nullptr) {
                Log(LOG_LEVEL_ERROR) << "Certificate with ID:" << certId << " not found";
                return "{\"success\": false, \"error\": \"Certificate not found\"}";
            }

            TxPool& txPool = TxPool::Instance();
            TxIn *txIn = new TxIn();

            UAmount inAmount;
            txIn->setAmount(inAmount);
            txIn->setNonce(cert->getNonce());
            txIn->setInAddress(certId);


            std::vector<TxIn> txIns;
            txIns.emplace_back(*txIn);

            Transaction* tx = new Transaction();
            tx->setNetwork(NET_CURRENT);
            tx->setTxIns(txIns);

            std::vector<unsigned char> txId = TransactionHelper::getTxId(tx);
            std::vector<unsigned char> privKey = Hexdump::hexStringToVector(UBIC_ROOT_PRIVATE_KEY);
            std::vector<unsigned char> signature = CreateSignature::sign(privKey, txId);

            DeactivateCertificateScript deactivateCertificateScript;
            deactivateCertificateScript.type = type;
            deactivateCertificateScript.rootCertSignature = signature;

            CDataStream s(SER_DISK, 1);
            s << deactivateCertificateScript;

            UScript script;
            script.setScript((unsigned char*)s.data(), (uint16_t)s.size());
            script.setScriptType(SCRIPT_DEACTIVATE_CERTIFICATE);
            txIn->setScript(script);

            std::vector<TxIn> txIns2;
            txIns.emplace_back(*txIn);
            tx->setTxIns(txIns2);

            txPool.appendTransaction(*tx);
        }
    }

    return "{\"success\": false}";
}
