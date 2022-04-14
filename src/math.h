//
// Created by gpr on 16/03/2022.
//

#ifndef THREATS_SEAL_MATH_H
#define THREATS_SEAL_MATH_H


#include <seal/seal.h>

using namespace std;
using namespace seal;

double manhattan_distance(std::vector<double> v1, std::vector<double> v2);
double euclidean_distance(std::vector<double> v1, std::vector<double> v2);

void enc_manhattan_dist(const Ciphertext &ct1, const Ciphertext &ct2, Ciphertext &ctdest, CKKSEncoder &encoder,
                         Evaluator &evaluator, const GaloisKeys &gal_keys);

void enc_euclidean_dist(const Ciphertext &ct1, const Ciphertext &ct2, Ciphertext &ctdest, CKKSEncoder &encoder,
                         Evaluator &evaluator, const GaloisKeys &gal_keys, const RelinKeys &relin_keys, const double scale);

#endif //THREATS_SEAL_MATH_H
