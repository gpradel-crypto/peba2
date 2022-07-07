//
// Created by gpradel on 7/5/2022.
//

#ifndef THREATS_SEAL_HOMOMORPHIC_MATH_H
#define THREATS_SEAL_HOMOMORPHIC_MATH_H

#include <seal/seal.h>

void
enc_manhattan_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2,
                   seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                   seal::Evaluator &evaluator,
                   const seal::GaloisKeys &gal_keys);

void
enc_euclidean_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2,
                   seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                   seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys,
                   const seal::RelinKeys &relin_keys, const double scale);

void enc_final_approx_inplace(seal::Ciphertext &ct, seal::CKKSEncoder &encoder,
                              seal::Decryptor &decryptor,
                              seal::Evaluator &evaluator,
                              const double scale);

void enc_f1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator, const seal::RelinKeys &relin_keys,
            const double scale);

void enc_f2(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_f3(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_f4(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_g1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_g2(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_g3(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void enc_g4(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale);

void decrypt_decode_print(seal::Ciphertext &ct, seal::CKKSEncoder &encoder,
                          seal::Decryptor &decryptor);

#endif //THREATS_SEAL_HOMOMORPHIC_MATH_H
