//
// Created by gpr on 16/03/2022.
//

#include "math.h"

double manhattan_distance(std::vector<double> v1, std::vector<double> v2){
    if (v1.size() != v2.size())
        abort();
    double result = 0.0;
    for (int i = 0; i < v1.size(); ++i) {
        result += v2[i] - v1[i];
    }
    return result;
}

double euclidean_distance(std::vector<double> v1, std::vector<double> v2){
    if (v1.size() != v2.size())
        abort();
    double result = 0.0;
    for (int i = 0; i < v1.size(); ++i) {
        result += pow(v2[i] - v1[i], 2);
    }
    return result;
}

/*
 * Computation of the manhattan distance between two ciphertexts ct1 and ct2.
 * The result is put in ctdest.
 * NOTA BENE: The current code is not robust, as the absolute value is never done (shall be done at each subtraction).
 */
void enc_manhattan_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                        seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys) {
    evaluator.sub(ct2, ct1, ctdest);
    for (size_t i = 1; i <= encoder.slot_count() / 2; i <<= 1) {
        seal::Ciphertext temp_ct;
        evaluator.rotate_vector(ctdest, i, gal_keys, temp_ct);
        evaluator.add_inplace(ctdest, temp_ct);
    }
}

/*
 * Computation of the euclidean distance between two ciphertexts ct1 and ct2. The square root at the end is not computed.
 * The result is put in ctdest.
 */
void enc_euclidean_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                        seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys, const seal::RelinKeys &relin_keys, const double scale) {
    evaluator.sub(ct2, ct1, ctdest);
    evaluator.square_inplace(ctdest);
    evaluator.relinearize_inplace(ctdest, relin_keys);
    seal::Ciphertext temp_ct;
    for (size_t i = 1; i <= encoder.slot_count() / 2; i <<= 1) {
        evaluator.rotate_vector(ctdest, i, gal_keys, temp_ct);
        evaluator.add_inplace(ctdest, temp_ct);
    }
    //rescaling
    //evaluator.relinearize_inplace(ctdest, relin_keys);
//    evaluator.rescale_to_next_inplace(ctdest);
//    ctdest.scale() = scale;
//    evaluator.transform_to_ntt_inplace(ctdest);
}