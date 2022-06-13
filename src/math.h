//
// Created by gpr on 16/03/2022.
//

#ifndef THREATS_SEAL_MATH_H
#define THREATS_SEAL_MATH_H


#include <seal/seal.h>


double manhattan_distance(std::vector<double> v1, std::vector<double> v2);
double euclidean_distance(std::vector<double> v1, std::vector<double> v2);

void enc_manhattan_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                        seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys);

void enc_euclidean_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                        seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys, const seal::RelinKeys &relin_keys, const double scale);

#endif //THREATS_SEAL_MATH_H
