/**
 *
 * With UBIC the UBI reward is distributed every block to a large amount of addresses. This is why
 * The PathSum Class is there to drastically reduce the amount of computation required for every payout.
 *
 * Example:
 *
 *                                          158
 *
 *                  87                                            71
 *
 *        45                    42                      30                   41
 *
 * 5 5 5 5 5 4 4 4 4 4 | 5 5 5 5 5 5 3 3 3 3 | 3 3 3 3 3 3 3 3 3 3 | 4 5 4 4 4 4 4 4 4 4
 *
 * In this example without the PathSum it would take 22 computational steps to calculate
 * the UBI reward between Block 0 and 22. With the PathSum it takes only 3:
 * 87 + 3 + 3
 *
 */

#ifndef PATH_SUM_H
#define PATH_SUM_H

#include <map>
#include "../UAmount.h"

class PathSum {
private:
    std::map<uint64_t, UAmount> stack;
    std::map<uint64_t, UAmount> babySteps; // *10
    std::map<uint64_t, UAmount> littleSteps; // *100
    std::map<uint64_t, UAmount> normalSteps; // *1000
    std::map<uint64_t, UAmount> bigSteps; // *10000
    std::map<uint64_t, UAmount> hugeSteps; // *100000
    std::map<uint64_t, UAmount> giantSteps; // *1000000

    int64_t BABY_STEP = 10;
    int64_t LITTLE_STEP = 100;
    int64_t NORMAL_STEP = 1000;
    int64_t BIG_STEP = 10000;
    int64_t HUGE_STEP = 100000;
    int64_t GIANT_STEP = 1000000;
public:
    static PathSum& Instance(){
        static PathSum instance;
        return instance;
    }

    bool appendValue(UAmount amount);
    bool popValue(uint64_t size);
    UAmount getSum(uint64_t startPosition, uint64_t endPosition);
    uint64_t getStackHeight();
    std::map<uint64_t, UAmount> getStack();
};


#endif //PATH_TREE_H
