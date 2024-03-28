#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "plain_math.h"

#include <iostream>

// #include "utilities.h"

void PrintVectorIntAdHoc(std::vector<int64_t> vect) {
    if (vect.empty()) {
        perror("Vector empty for print in stdout");
        abort();
    }
    std::cout << "[ ";
    for (int i = 0; i < 128; i++) {
        std::cout << vect[i] << ", ";
    }
    std::cout << vect[128] << " ]";
    std::cout << std::endl << std::endl;
}

double manhattan_distance(std::vector<double> v1, std::vector<double> v2) {
    if (v1.size() != v2.size())
        abort();
    double result = 0.0;
    for (int i = 0; i < v1.size(); ++i) {
        result += v2[i] - v1[i];
    }
    return result;
}

double euclidean_distance(std::vector<double> v1, std::vector<double> v2) {
    if (v1.size() != v2.size())
        abort();
    double result = 0.0;
    for (int i = 0; i < v1.size(); ++i) {
        result += pow(v2[i] - v1[i], 2);
    }
    return result;
}

int64_t euclidean_distance_int(std::vector<int64_t> v1, std::vector<int64_t> v2) {
    if (v1.size() != v2.size())
        abort();
    int64_t result = 0;
    std::vector<int64_t> intermediate_result;
    std::vector<int64_t> intermediate_result2;
    // std::cout << "Vector v1" << std::endl;
    // PrintVectorIntAdHoc(v1);
    // std::cout << "Vector v2" << std::endl;
    // PrintVectorIntAdHoc(v2);
    for (int i = 0; i < v1.size(); ++i) {
        intermediate_result.push_back(v2[i] - v1[i]);
    }
    // std::cout << "Vector v2 - v1" << std::endl;
    // PrintVectorIntAdHoc(intermediate_result);
    for (int i = 0; i < intermediate_result.size(); ++i)
        intermediate_result2.push_back(pow(intermediate_result[i], 2));
    // std::cout << "Vector pow(v2 - v1, 2)" << std::endl;
    // PrintVectorIntAdHoc(intermediate_result2);
    // for (int i = 0; i < v1.size(); ++i) {
        // result += pow(v2[i] - v1[i], 2);
    // }
    // I don't understand but the operation above simply does not work
    for (int i = 0; i < v1.size(); ++i)
        result += intermediate_result2[i];
    return result;
}

void final_approx_inplace(double& x){
    x+=1;
    x/=2;
}

double f1(double x) {
    return (-1.0 / 2.0) * pow(x, 3) + (3.0 / 2.0) * x;
}

double f2(double x) {
    return (3.0 / 8.0) * pow(x, 5) - (10.0 / 8.0) * pow(x, 3) +
           (15.0 / 8.0) * x;
}

double f3(double x) {
    return (-5.0 / 16.0) * pow(x, 7) + (21.0 / 16.0) * pow(x, 5) -
           (35.0 / 16.0) * pow(x, 3) + (35.0 / 16.0) * x;
}

double f4(double x) {
    return (35.0 / 128.0) * pow(x, 9) - (180.0 / 128.0) * pow(x, 7) +
           (378.0 / 128.0) * pow(x, 5) - (420.0 / 128.0) * pow(x, 3) +
           (315.0 / 128.0) * x;
}

double g1(double x) {
    return (-1359.0 / pow(2.0, 10)) * pow(x, 3) + (2126.0 / pow(2.0, 10)) * x;
}

double g2(double x) {
    return (3796.0 / pow(2.0, 10)) * pow(x, 5) -
           (6108.0 / pow(2.0, 10)) * pow(x, 3) + (3334.0 / pow(2.0, 10)) * x;
}

double g3(double x) {
    return (-12860.0 / pow(2.0, 10)) * pow(x, 7) +
           (25614.0 / pow(2.0, 10)) * pow(x, 5) -
           (16577.0 / pow(2.0, 10)) * pow(x, 3) + (4589.0 /
                                                   pow(2.0, 10)) * x;
}

double g4(double x) {
    return (46623.0 / pow(2.0, 10)) * pow(x, 9) -
           (113492.0 / pow(2.0, 10)) * pow(x, 7) +
           (97015.0 / pow(2.0, 10)) * pow(x, 5) - (34974.0 /
                                                   pow(2.0, 10)) * pow(x, 3) +
           (5850.0 /
            pow(2.0, 10)) * x;
}

int64_t Lagrange_257(int64_t x) {
    return 64*pow(x,126) + 111*pow(x,125) + 2*pow(x,123) + 126*pow(x,121) + 9*pow(x,119) + 6*pow(x,117) + 56*pow(x,115) + 112*pow(x,111) + 56*pow(x,109) + 120*pow(x,107) + 100*pow(x,105) + 119*pow(x,103) + 99*pow(x,101) + 12*pow(x,97) + 19*pow(x,95) + 29*pow(x,93) + 96*pow(x,91) + 38*pow(x,89) + 26*pow(x,87) + 92*pow(x,83) + 4*pow(x,81) + 22*pow(x,79) + 125*pow(x,77) + 96*pow(x,75) + 41*pow(x,73) + 86*pow(x,69) + 74*pow(x,67) + 63*pow(x,65) + 5*pow(x,63) + 115*pow(x,61) + 57*pow(x,59) + 93*pow(x,55) + 12*pow(x,53) + 42*pow(x,51) + 99*pow(x,49) + 48*pow(x,47) + 123*pow(x,45) + 91*pow(x,41) + 109*pow(x,39) + 93*pow(x,37) + 118*pow(x,35) + 113*pow(x,33) + 21*pow(x,31) + 81*pow(x,27) + 111*pow(x,25) + 26*pow(x,23) + 31*pow(x,21) + 91*pow(x,19) + 38*pow(x,17) + 75*pow(x,13) + 87*pow(x,11) + 42*pow(x,9) + 97*pow(x,7) + 68*pow(x,5) + 30*pow(x,3) + 91*x;
}