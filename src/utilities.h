//
// Created by gpr on 16/03/2022.
//

#ifndef THREATS_SEAL_UTILITIES_H
#define THREATS_SEAL_UTILITIES_H

#include <iostream>
#include <chrono>
#include <vector>

constexpr double LOWER_BOUND = -1.0;
constexpr double UPPER_BOUND = 1.0;

class Stopwatch
{
public:
    Stopwatch(std::string timer_name) :
            name_(timer_name),
            start_time_(std::chrono::high_resolution_clock::now())
    {
    }

    ~Stopwatch()
    {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
        std::cout << name_ << ": " << duration.count() << " milliseconds" << std::endl;
    }

private:
    std::string name_;
    std::chrono::high_resolution_clock::time_point start_time_;
};

double random_double(void);
std::vector<double> create_vector_input(size_t dimension);
std::vector<double> create_vector_input_chosen(size_t dimension, double value);
void print_vector(std::vector<double> vect);
void print_parameters(const seal::SEALContext &context);
std::vector<char> FromFileToVect(std::string filename);

#endif //THREATS_SEAL_UTILITIES_H
