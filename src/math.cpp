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

double polynomial_approx_sign(double x){
    // the polynomial is -2x^3 + 3x^2
    double result = -2* pow(x, 3) + 3 * pow(x, 2);
    return result;
}

double comp_approx(double x){
    double result = (polynomial_approx_sign(x) + 1)/2;
    return result;
}

double f1(double x){
    double result = (-1.0/2.0)*pow(x, 3) + (3.0/2.0)*x;
    return result;
}

double f2(double x){
    double result = (3.0/8.0)* pow(x, 5) - (10.0/8.0)*pow(x,3) + (15.0/8.0)* x;
    return result;
}

double f3(double x){
    double result = (-5.0/16.0)*pow(x,7) + (21.0/16.0)* pow(x, 5) - (35.0/16.0)*pow(x,3) + (35.0/16.0)*x;
    return result;
}

void enc_f1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys, const seal::RelinKeys &relin_keys, const double scale){
    double a3 = -1.0/2.0;
    double a1 = 3.0/2.0;
//    std::cout << "ct_x egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Plaintext a3_pt, a1_pt;
    encoder.encode(a1, scale, a1_pt);
    encoder.encode(a3, scale, a3_pt);
    seal::Ciphertext ct_x2;
    evaluator.square(ct_x, ct_x2);
//    std::cout << "ct_x2 avant rescale et relin egale a " << std::endl;
//    decrypt_decode_print(ct_x2, encoder, decryptor);
    evaluator.relinearize_inplace(ct_x2, relin_keys);
//    std::cout << "ct_x2 apres relin egale a " << std::endl;
//    decrypt_decode_print(ct_x2, encoder, decryptor);
    evaluator.rescale_to_next_inplace(ct_x2);
//    std::cout << "ct_x2 apres rescale egale a " << std::endl;
//    decrypt_decode_print(ct_x2, encoder, decryptor);
    evaluator.mod_switch_to_inplace(ct_x, ct_x2.parms_id());
//    std::cout << "ct_x apres rescale egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Ciphertext ct_x3;
    evaluator.multiply(ct_x2, ct_x, ct_x3);
//    std::cout << "ct_x3 avant rescale et relin egale a " << std::endl;
//    decrypt_decode_print(ct_x3, encoder, decryptor);
    evaluator.relinearize_inplace(ct_x3, relin_keys);
//    std::cout << "ct_x3 apres relin egale a " << std::endl;
//    decrypt_decode_print(ct_x3, encoder, decryptor);
    evaluator.rescale_to_next_inplace(ct_x3);
//    std::cout << "ct_x3 apres rescale egale a " << std::endl;
//    decrypt_decode_print(ct_x3, encoder, decryptor);
    evaluator.mod_switch_to_inplace(a3_pt, ct_x3.parms_id());
    evaluator.multiply_plain_inplace(ct_x3, a3_pt);
//    std::cout << "ct_x3 apres mult plain egale a " << std::endl;
//    decrypt_decode_print(ct_x3, encoder, decryptor);
    evaluator.mod_switch_to_inplace(a1_pt, ct_x.parms_id());
    evaluator.multiply_plain_inplace(ct_x, a1_pt);
//    std::cout << "ct_x apres mult plain egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
//    evaluator.rescale_to_next_inplace(ct_x);
    evaluator.rescale_to_inplace(ct_x, ct_x3.parms_id());
//    std::cout << "ct_x apres rescale egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
    evaluator.rescale_to_next_inplace(ct_x3);
    evaluator.mod_switch_to_inplace(ct_x, ct_x3.parms_id());
    ct_x3.scale() = ct_x.scale();
//    std::cout << "ct_x apres brute force scaling egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
//    std::cout << "ct_x3 apres brute force scaling egale a " << std::endl;
//    decrypt_decode_print(ct_x3, encoder, decryptor);
    evaluator.add(ct_x3, ct_x, ctdest);
    std::cout << "ct_dest  egale a " << std::endl;
    decrypt_decode_print(ctdest, encoder, decryptor);
}

void enc_final_output_inplace(seal::Ciphertext &ct, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
                              seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys,
                              const seal::RelinKeys &relin_keys, const double scale){
    double one = 1.0;
    double half = 0.5;
    seal::Plaintext one_pt, half_pt;
    encoder.encode(one, scale, one_pt);
    encoder.encode(half, scale, half_pt);
    evaluator.mod_switch_to_inplace(one_pt, ct.parms_id());
    one_pt.scale() = ct.scale();
    evaluator.add_plain_inplace(ct, one_pt);
    evaluator.mod_switch_to_inplace(half_pt, ct.parms_id());
    evaluator.multiply_plain_inplace(ct, half_pt);
    evaluator.rescale_to_next_inplace(ct);
}

void decrypt_decode_print(seal::Ciphertext &ct, seal::CKKSEncoder &encoder, seal::Decryptor &decryptor){
    seal::Plaintext tmp_pt;
    std::vector<double> tmp;
    decryptor.decrypt(ct, tmp_pt);
    encoder.decode(tmp_pt, tmp);
    std::cout << "[ ";
    for (int i = 0; i < 10; i++) {
        std::cout << tmp[i] << ", ";
    }
    std::cout << tmp[10] << " ]";
    std::cout << std::endl << std::endl;
}