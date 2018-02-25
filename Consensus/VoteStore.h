
#ifndef TX_VOTESTORE_H
#define TX_VOTESTORE_H

#include <vector>
#include "Delegate.h"
#include "../FS/FS.h"
#include "Vote.h"
#include "../Crypto/VerifySignature.h"
#include "../Chain.h"
#include "../DB/DB.h"

class VoteStore {
private:
    std::map<std::vector<unsigned char>, Delegate> activeDelegates;
    std::map<std::vector<unsigned char>, Delegate> allDelegates;

    int32_t getMinRequiredScore(std::map<std::vector<unsigned char>, Delegate> delegates) {
        int32_t minScore = UINT_MAX;

        for(auto delegate: delegates) {
            if(minScore > (delegate.second.getTotalVote())) {
                minScore = delegate.second.getTotalVote();
            }
        }

        return minScore + 1;
    }

    std::map<std::vector<unsigned char>, Delegate> removeDelegatesWithScoreUnder(
            std::map<std::vector<unsigned char>, Delegate> delegates, int32_t minScore
    ) {
        for(std::map<std::vector<unsigned char>, Delegate>::iterator it = delegates.begin(); it != delegates.end();) {
            if((it->second.getVoteCount() - it->second.getUnVoteCount()) < minScore) {
                it = delegates.erase(it);
            } else {
                it++;
            }
        }

        return delegates;
    }


public:
    static VoteStore& Instance(){
        static VoteStore instance;
        return instance;
    }

    std::map<std::vector<unsigned char>, Delegate> getActiveDelegates() {
        return this->activeDelegates;
    }

    std::map<std::vector<unsigned char>, Delegate> getAllDelegates() {
        return this->allDelegates;
    }

    bool loadDelegates() {
        DB& db = DB::Instance();
        for(std::vector<unsigned char> key : db.getAllKeys(DB_VOTES)) {
            Delegate* delegate = new Delegate();
            if(!db.deserializeFromDb(DB_VOTES, key, *delegate)) {
                return false;
            }
            this->allDelegates.insert(std::make_pair(delegate->getPublicKey(), *delegate));
        }

        Log(LOG_LEVEL_INFO) << "this->allDelegates.size(): " << this->allDelegates.size();

        std::map<std::vector<unsigned char>, Delegate> delegateCandidates;
        for(auto delegate1 : this->allDelegates) {
            int32_t score = delegate1.second.getTotalVote();
            if(score >= MINIMUM_DELEGATE_VOTES) {
                delegateCandidates.insert(delegate1);
            }
        }

        if(delegateCandidates.size() <= MAXIMUM_DELEGATE_COUNT) {
            this->activeDelegates = delegateCandidates;
        } else {
            // @TODO test this code!
            // Keep only the best 51
            // however if delegate 51 and 52 have the same amount of votes take none of them
            uint32_t minRequiredScore = 0;

            std::map<std::vector<unsigned char>, Delegate> delegates;

            for(auto delegate : delegateCandidates) {
                if(delegates.size() < MAXIMUM_DELEGATE_COUNT) {
                    delegates.insert(delegate);
                } else {
                    int32_t minScore = this->getMinRequiredScore(delegates);

                    if(delegate.second.getTotalVote() >= minScore) {
                        delegates = this->removeDelegatesWithScoreUnder(delegates, minScore);
                        delegates.insert(delegate);
                    }
                }
            }

            this->activeDelegates = delegates;
        }

        Log(LOG_LEVEL_INFO) << "this->activeDelegates.size(): " << this->activeDelegates.size();

        return true;
    }

    bool verifyVote(Vote* vote) {
        Chain& chain = Chain::Instance();
        auto fromDelegate = this->activeDelegates.find(vote->getFromPubKey());

        if(vote->getFromPubKey() == vote->getTargetPubKey()) {
            Log(LOG_LEVEL_ERROR) << "A Delegate cannot vote for himself";
            return false;
        }

        if(fromDelegate == this->activeDelegates.end()) {
            Log(LOG_LEVEL_ERROR) << "Vote was issued by a public key that isn't in delegate list";
            return false;
        }

        if(chain.getCurrentBlockchainHeight() < chain.getBlockHeight(fromDelegate->second.getBlockHashLastVote()) + VOTES_INTERVAL) {
            Log(LOG_LEVEL_ERROR) << "Votes are only allowed every: " << VOTES_INTERVAL << " blocks";
            return false;
        }

        if(vote->getAction() != VOTE_ACTION_VOTE && vote->getAction() != VOTE_ACTION_UNVOTE) {
            Log(LOG_LEVEL_ERROR) << "Unkown vote action: " << vote->getAction();
            return false;
        }

        if(fromDelegate->second.getNonce() != vote->getNonce()) {
            Log(LOG_LEVEL_ERROR) << "nonce mismatch between fromDelegate and vote";
            return false;
        }

        for(auto dVote: fromDelegate->second.getVotes()) {
            if(dVote.getTargetPubKey() == vote->getTargetPubKey() && dVote.getAction() == vote->getAction()) {
                Log(LOG_LEVEL_ERROR) << "Cannot vote or unvote the same delegate ("
                                     << dVote.getTargetPubKey()
                                     << ") multiple times";
                return false;
            }
        }

        return true;
    }

    void undoVote(Vote* vote) {

        Chain& chain = Chain::Instance();
        Log(LOG_LEVEL_INFO) << "undoing vote from: " << vote->getFromPubKey() << " to: " << vote->getTargetPubKey();
        auto fromDelegate = this->activeDelegates.find(vote->getFromPubKey());
        auto votes = fromDelegate->second.getVotes();
        bool undoedPreviousVote = false;

        // undo previous opposite vote if there is.
        // For example if there is a previous unvote and now a vote the vote undo the unvote
        for(std::vector<Vote>::iterator it = votes.begin(); it != votes.end();) {
            if(it->getTargetPubKey() == vote->getTargetPubKey()) {
                it = votes.erase(it);
                fromDelegate->second.setVotes(votes);
                Log(LOG_LEVEL_INFO) << "undoing previous vote";
                undoedPreviousVote = true;
            } else {
                it++;
            }
        }

        Delegate* targetDelegate = new Delegate();
        DB& db = DB::Instance();

        if(!db.deserializeFromDb(DB_VOTES, vote->getTargetPubKey(), *targetDelegate)) {
            Log(LOG_LEVEL_INFO) << "Delegate: "
                                << vote->getTargetPubKey()
                                << " doesn't exist yet";
            targetDelegate->setPublicKey(vote->getTargetPubKey());
            targetDelegate->setNonce(0);
            targetDelegate->setBlockHashLastVote(chain.getBestBlockHeader()->getHeaderHash());
            targetDelegate->setVoteCount(0);
            targetDelegate->setUnVoteCount(0);
        }

        if(!undoedPreviousVote) {
            // reverse the vote to undo VOTE becomes UNVOTE, UNVOTE becomes VOTE
            if(vote->getAction() == VOTE_ACTION_VOTE) {
                vote->setAction(VOTE_ACTION_UNVOTE);
            } else {
                vote->setAction(VOTE_ACTION_VOTE);
            }
            fromDelegate->second.appendVote(vote);
        }
        fromDelegate->second.setNonce(fromDelegate->second.getNonce() - 1);

        switch(vote->getAction()) {
            case VOTE_ACTION_VOTE:
                targetDelegate->setVoteCount(targetDelegate->getVoteCount() - 1);
                break;
            case VOTE_ACTION_UNVOTE:
                targetDelegate->setUnVoteCount(targetDelegate->getUnVoteCount() - 1);
                break;
            default:
                Log(LOG_LEVEL_CRITICAL_ERROR) << "Unkown vote action: " << vote->getAction() << " when applying vote";
                return;
        }

        if(!db.serializeToDb(DB_VOTES, vote->getTargetPubKey(), *targetDelegate)) {
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot serialize delegate to DB";
        }

        if(!db.serializeToDb(DB_VOTES, fromDelegate->second.getPublicKey(), fromDelegate->second)) {
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot serialize delegate to DB";
        }

        // reload delegates
        this->allDelegates.clear();
        this->activeDelegates.clear();
        loadDelegates();
    }

    void applyVote(Vote* vote) {
        Chain& chain = Chain::Instance();
        Log(LOG_LEVEL_INFO) << "applying vote from: " << vote->getFromPubKey() << " to: " << vote->getTargetPubKey();
        auto fromDelegate = this->activeDelegates.find(vote->getFromPubKey());
        auto votes = fromDelegate->second.getVotes();
        bool undoedPreviousVote = false;

        // undo previous opposite vote if there is.
        // For example if there is a previous unvote and now a vote the vote undo the unvote
        for(std::vector<Vote>::iterator it = votes.begin(); it != votes.end();) {
            if(it->getTargetPubKey() == vote->getTargetPubKey()) {
                it = votes.erase(it);
                fromDelegate->second.setVotes(votes);
                Log(LOG_LEVEL_INFO) << "undoing previous vote";
                undoedPreviousVote = true;
            } else {
                it++;
            }
        }

        Delegate* targetDelegate = new Delegate();
        DB& db = DB::Instance();

        if(!db.deserializeFromDb(DB_VOTES, vote->getTargetPubKey(), *targetDelegate)) {
            Log(LOG_LEVEL_INFO) << "Delegate: "
                                << vote->getTargetPubKey()
                                << " doesn't exist yet";
            targetDelegate->setPublicKey(vote->getTargetPubKey());
            targetDelegate->setNonce(0);
            targetDelegate->setBlockHashLastVote(chain.getBestBlockHeader()->getHeaderHash());
            targetDelegate->setVoteCount(0);
            targetDelegate->setUnVoteCount(0);
        }

        if(!undoedPreviousVote) {
            fromDelegate->second.appendVote(vote);
        }
        fromDelegate->second.setNonce(fromDelegate->second.getNonce() + 1);

        switch(vote->getAction()) {
            case VOTE_ACTION_VOTE:
                targetDelegate->setVoteCount(targetDelegate->getVoteCount() + 1);
                break;
            case VOTE_ACTION_UNVOTE:
                targetDelegate->setUnVoteCount(targetDelegate->getUnVoteCount() + 1);
                break;
            default:
                Log(LOG_LEVEL_CRITICAL_ERROR) << "Unkown vote action: " << vote->getAction() << " when applying vote";
                return;
        }

        if(!db.serializeToDb(DB_VOTES, vote->getTargetPubKey(), *targetDelegate)) {
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot serialize delegate to DB";
        }

        if(!db.serializeToDb(DB_VOTES, fromDelegate->second.getPublicKey(), fromDelegate->second)) {
            Log(LOG_LEVEL_CRITICAL_ERROR) << "Cannot serialize delegate to DB";
        }

        // reload delegates
        this->allDelegates.clear();
        this->activeDelegates.clear();
        loadDelegates();
    }

    std::vector<unsigned char> getValidatorForTimestamp(uint64_t timestamp) {
        if(this->activeDelegates.size() == 0) {
            return std::vector<unsigned char>();
        }
        uint64_t delegateNbr = ((uint64_t)(timestamp / BLOCK_INTERVAL_IN_SECONDS) % this->activeDelegates.size());
        Log(LOG_LEVEL_INFO) << "this->activeDelegates.size(): " << this->activeDelegates.size();
        Log(LOG_LEVEL_INFO) << "current delegateNbr: " << delegateNbr;
        uint32_t i = 0;
        for(auto activeDelegate : this->activeDelegates) {
            if(i == delegateNbr) {
                return activeDelegate.second.getPublicKey();
            }
            i++;
        }

        Log(LOG_LEVEL_CRITICAL_ERROR) << "getValidatorForTimestamp(): out of range";
        return std::vector<unsigned char>();
    }

};


#endif //TX_VOTESTORE_H
