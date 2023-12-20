#ifndef PIREXAMPLE_H
#define PIREXAMPLE_H

#include "util.h"


template<typename T>
class random_generator {};

template<>
class random_generator<int> {
// Type int is for BGV and BFV
// Type double for CKKS can also be realized
public:
    random_generator(std::size_t max_value) : max_value_(max_value) {
        srand(time(NULL));
    }

    std::size_t operator()() {
        std::size_t result  = rand() % max_value_;
        return result;
    }

private:
    std::size_t max_value_;
};

void PIRExample(std::size_t index, std::size_t database_size);

#endif
