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
double polynomial_approx_sign(double x);
double comp_approx(double x);
double f1(double x);
double f2(double x);
double f3(double x);
void enc_f1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys, const seal::RelinKeys &relin_keys, const double scale);
void enc_final_output_inplace(seal::Ciphertext &ct, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
                              seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys,
                              const seal::RelinKeys &relin_keys, const double scale);
void decrypt_decode_print(seal::Ciphertext &ct, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor);
#endif //THREATS_SEAL_MATH_H
