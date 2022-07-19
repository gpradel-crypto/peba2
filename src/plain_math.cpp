#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "plain_math.h"


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