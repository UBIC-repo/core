
#include "PathSum.h"
#include "../Tools/Log.h"

bool PathSum::appendValue(UAmount amount) {
    this->stack[(unsigned int)this->stack.size()] = amount;

    if(this->stack.size() % BABY_STEP == 0 && this->stack.size() >= BABY_STEP) {
        UAmount babySum = getSum((uint64_t)this->stack.size() - BABY_STEP, (uint64_t)this->stack.size());
        this->babySteps[(uint64_t)this->stack.size() - BABY_STEP] = babySum;
    }
    if(this->stack.size() % LITTLE_STEP == 0 && this->stack.size() >= LITTLE_STEP) {
        UAmount littleSum = getSum((uint64_t)this->stack.size() - LITTLE_STEP, (uint64_t)this->stack.size());
        this->littleSteps[(uint64_t)this->stack.size() - LITTLE_STEP] = littleSum;
    }
    if(this->stack.size() % NORMAL_STEP == 0 && this->stack.size() >= NORMAL_STEP) {
        UAmount normalSum = getSum((uint64_t)this->stack.size() - NORMAL_STEP, (uint64_t)this->stack.size());
        this->normalSteps[(uint64_t)this->stack.size() - NORMAL_STEP] = normalSum;
    }
    if(this->stack.size() % BIG_STEP == 0 && this->stack.size() >= BIG_STEP) {
        UAmount bigSum = getSum((uint64_t)this->stack.size() - BIG_STEP, (uint64_t)this->stack.size());
        this->bigSteps[(uint64_t)this->stack.size() - BIG_STEP] = bigSum;
    }
    if(this->stack.size() % HUGE_STEP == 0 && this->stack.size() >= HUGE_STEP) {
        UAmount hugeSum = getSum((uint64_t)this->stack.size() - HUGE_STEP, (uint64_t)this->stack.size());
        this->hugeSteps[(uint64_t)this->stack.size() - HUGE_STEP] = hugeSum;
    }
    if(this->stack.size() % GIANT_STEP == 0 && this->stack.size() >= GIANT_STEP) {
        UAmount giantSum = getSum((uint64_t)this->stack.size() - GIANT_STEP, (uint64_t)this->stack.size());
        this->giantSteps[(uint64_t)this->stack.size() - GIANT_STEP] = giantSum;
    }

    return true;
}

UAmount PathSum::getSum(uint64_t startPosition, uint64_t endPosition) {
    //Log(LOG_LEVEL_INFO) << "getSum: " << startPosition << "," << endPosition;
    UAmount sum;
    uint64_t currentPosition = startPosition;

    while(currentPosition < endPosition) {
        if (currentPosition % GIANT_STEP == 0 && endPosition >= (currentPosition + GIANT_STEP)) {
            if(this->giantSteps.find(currentPosition) != this->giantSteps.end()) {
                sum += this->giantSteps[currentPosition];
                //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do GIANT_STEP +" << this->giantSteps[currentPosition];
                currentPosition += GIANT_STEP;
                continue;
            }
        }
        if (currentPosition % HUGE_STEP == 0 && endPosition >= (currentPosition + HUGE_STEP)) {
            if(this->hugeSteps.find(currentPosition) != this->hugeSteps.end()) {
                sum += this->hugeSteps[currentPosition];
                //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do HUGE_STEP +" << this->hugeSteps[currentPosition];
                currentPosition += HUGE_STEP;
                continue;
            }
        }
        if (currentPosition % BIG_STEP == 0 && endPosition >= (currentPosition + BIG_STEP)) {
            if(this->bigSteps.find(currentPosition) != this->bigSteps.end()) {
                sum += this->bigSteps[currentPosition];
                Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do BIG_STEP +" << this->bigSteps[currentPosition];
                currentPosition += BIG_STEP;
                continue;
            }
        }
        if (currentPosition % NORMAL_STEP == 0 && endPosition >= (currentPosition + NORMAL_STEP)) {
            if(this->normalSteps.find(currentPosition) != this->normalSteps.end()) {
                sum += this->normalSteps[currentPosition];
                //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do NORMAL_STEP +" << this->normalSteps[currentPosition];
                currentPosition += NORMAL_STEP;
                continue;
            }
        }
        if (currentPosition % LITTLE_STEP == 0 && endPosition >= (currentPosition + LITTLE_STEP)) {
            if(this->littleSteps.find(currentPosition) != this->littleSteps.end()) {
                sum += this->littleSteps[currentPosition];
                //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do LITTLE_STEP +" << this->littleSteps[currentPosition];
                currentPosition += LITTLE_STEP;
                continue;
            }
        }
        if (currentPosition % BABY_STEP == 0 && endPosition >= (currentPosition + BABY_STEP)) {
            if(this->babySteps.find(currentPosition) != this->babySteps.end()) {
                sum += this->babySteps[currentPosition];
                //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do BABY_STEP +" << this->babySteps[currentPosition];
                currentPosition += BABY_STEP;
                continue;
            }
        }

        //do simple step
        if(this->stack.find(currentPosition) != this->stack.end()) {
            sum += this->stack[currentPosition];
            //Log(LOG_LEVEL_INFO) << "Position: " << currentPosition << " Do simple step +" << this->stack[currentPosition];
        }

        currentPosition += 1;
    }

    return sum;
}

bool PathSum::popValue(uint64_t size) {
    uint64_t oldStackHeight = PathSum::getStackHeight();
    for(uint64_t i = oldStackHeight; i > oldStackHeight - size; i--) {
        this->stack.erase(i);
    }

    return true;
}

uint64_t PathSum::getStackHeight() {
    return (uint64_t)this->stack.size();
}

std::map<uint64_t, UAmount> PathSum::getStack() {
    return this->stack;
}
