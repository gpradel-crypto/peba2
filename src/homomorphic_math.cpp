//
// Created by gpradel on 7/5/2022.
//

#include "homomorphic_math.h"


/*
 * Computation of the manhattan distance between two ciphertexts ct1 and ct2.
 * The result is put in ctdest.
 * NOTA BENE: The current code is not robust, as the absolute value is never done (shall be done at each subtraction).
 */
void
enc_manhattan_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2,
                   seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                   seal::Evaluator &evaluator,
                   const seal::GaloisKeys &gal_keys) {
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
void
enc_euclidean_dist(const seal::Ciphertext &ct1, const seal::Ciphertext &ct2,
                   seal::Ciphertext &ctdest, seal::CKKSEncoder &encoder,
                   seal::Evaluator &evaluator, const seal::GaloisKeys &gal_keys,
                   const seal::RelinKeys &relin_keys, const double scale) {
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

void enc_final_approx_inplace(seal::Ciphertext &ct, seal::CKKSEncoder &encoder,
                              seal::Decryptor &decryptor,
                              seal::Evaluator &evaluator,
                              const double scale) {
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


void enc_f1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale) {
    double a3 = -1.0 / 2.0;
    double a1 = 3.0 / 2.0;
//    std::cout << "ct_x egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Plaintext a3_pt, a1_pt;
    encoder.encode(a1, scale, a1_pt);
    encoder.encode(a3, scale, a3_pt);

    seal::Ciphertext ct_x2;
    evaluator.square(ct_x, ct_x2);
    evaluator.relinearize_inplace(ct_x2, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x2);

    evaluator.mod_switch_to_inplace(ct_x, ct_x2.parms_id());

    seal::Ciphertext ct_x3;
    evaluator.multiply(ct_x2, ct_x, ct_x3);
    evaluator.relinearize_inplace(ct_x3, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a3_pt, ct_x3.parms_id());
    evaluator.multiply_plain_inplace(ct_x3, a3_pt);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a1_pt, ct_x.parms_id());
    evaluator.multiply_plain_inplace(ct_x, a1_pt);
    evaluator.rescale_to_next_inplace(ct_x);

    evaluator.mod_switch_to_inplace(ct_x, ct_x3.parms_id());
    ct_x.scale() = ct_x3.scale();
    evaluator.add(ct_x3, ct_x, ctdest);

    std::cout << "ct_dest  egale a " << std::endl;
    decrypt_decode_print(ctdest, encoder, decryptor);
}

void enc_f2(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale) {
    double a5 = 3.0/8.0;
    double a3 = -10.0 / 8.0;
    double a1 = 15.0 / 8.0;
    std::cout << "ct_x egale a " << std::endl;
    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Plaintext a5_pt, a3_pt, a1_pt;
    encoder.encode(a1, scale, a1_pt);
    encoder.encode(a3, scale, a3_pt);
    encoder.encode(a5, scale, a5_pt);

    seal::Ciphertext ct_x2;
    evaluator.square(ct_x, ct_x2);
    evaluator.relinearize_inplace(ct_x2, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x2);

    evaluator.mod_switch_to_inplace(ct_x, ct_x2.parms_id());

    seal::Ciphertext ct_x3;
    evaluator.multiply(ct_x2, ct_x, ct_x3);
    evaluator.relinearize_inplace(ct_x3, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x3);

    seal::Ciphertext ct_x5;
    evaluator.mod_switch_to(ct_x2, ct_x3.parms_id(), ct_x5);
    evaluator.multiply_inplace(ct_x5, ct_x3);
    evaluator.relinearize_inplace(ct_x5, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x5);

    evaluator.mod_switch_to_inplace(a5_pt, ct_x5.parms_id());
    evaluator.multiply_plain_inplace(ct_x5, a5_pt);
    evaluator.rescale_to_next_inplace(ct_x5);

    evaluator.mod_switch_to_inplace(a3_pt, ct_x3.parms_id());
    evaluator.multiply_plain_inplace(ct_x3, a3_pt);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a1_pt, ct_x.parms_id());
    evaluator.multiply_plain_inplace(ct_x, a1_pt);
    evaluator.rescale_to_next_inplace(ct_x);

    evaluator.mod_switch_to_inplace(ct_x, ct_x5.parms_id());
    evaluator.mod_switch_to_inplace(ct_x3, ct_x5.parms_id());
    ct_x.scale() = ct_x5.scale();
    ct_x3.scale() = ct_x5.scale();
    evaluator.add(ct_x3, ct_x, ctdest);
    evaluator.add_inplace(ctdest, ct_x5);
    std::cout << "ct_dest  egale a " << std::endl;
    decrypt_decode_print(ctdest, encoder, decryptor);
}

void enc_g1(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale) {
    double a3 = -1359.0 / pow(2.0, 10);
    double a1 = 2126.0 / pow(2.0,10);
    //    std::cout << "ct_x egale a " << std::endl;
//    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Plaintext a3_pt, a1_pt;
    encoder.encode(a1, scale, a1_pt);
    encoder.encode(a3, scale, a3_pt);

    seal::Ciphertext ct_x2;
    evaluator.square(ct_x, ct_x2);
    evaluator.relinearize_inplace(ct_x2, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x2);

    evaluator.mod_switch_to_inplace(ct_x, ct_x2.parms_id());

    seal::Ciphertext ct_x3;
    evaluator.multiply(ct_x2, ct_x, ct_x3);
    evaluator.relinearize_inplace(ct_x3, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a3_pt, ct_x3.parms_id());
    evaluator.multiply_plain_inplace(ct_x3, a3_pt);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a1_pt, ct_x.parms_id());
    evaluator.multiply_plain_inplace(ct_x, a1_pt);
    evaluator.rescale_to_next_inplace(ct_x);

    evaluator.mod_switch_to_inplace(ct_x, ct_x3.parms_id());
    ct_x.scale() = ct_x3.scale();
    evaluator.add(ct_x3, ct_x, ctdest);

    std::cout << "ct_dest  egale a " << std::endl;
    decrypt_decode_print(ctdest, encoder, decryptor);
}

void enc_g2(seal::Ciphertext &ct_x, seal::Ciphertext &ctdest,
            seal::CKKSEncoder &encoder, seal::Decryptor &decryptor,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relin_keys, const double scale) {
    double a5 = 3796.0/ pow(2.0,10);
    double a3 = -6108.0 / pow(2.0,10);
    double a1 = 3334.0 / pow(2.0,10);
    std::cout << "ct_x egale a " << std::endl;
    decrypt_decode_print(ct_x, encoder, decryptor);
    seal::Plaintext a5_pt, a3_pt, a1_pt;
    encoder.encode(a1, scale, a1_pt);
    encoder.encode(a3, scale, a3_pt);
    encoder.encode(a5, scale, a5_pt);

    seal::Ciphertext ct_x2;
    evaluator.square(ct_x, ct_x2);
    evaluator.relinearize_inplace(ct_x2, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x2);

    evaluator.mod_switch_to_inplace(ct_x, ct_x2.parms_id());

    seal::Ciphertext ct_x3;
    evaluator.multiply(ct_x2, ct_x, ct_x3);
    evaluator.relinearize_inplace(ct_x3, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x3);

    seal::Ciphertext ct_x5;
    evaluator.mod_switch_to(ct_x2, ct_x3.parms_id(), ct_x5);
    evaluator.multiply_inplace(ct_x5, ct_x3);
    evaluator.relinearize_inplace(ct_x5, relin_keys);
    evaluator.rescale_to_next_inplace(ct_x5);

    evaluator.mod_switch_to_inplace(a5_pt, ct_x5.parms_id());
    evaluator.multiply_plain_inplace(ct_x5, a5_pt);
    evaluator.rescale_to_next_inplace(ct_x5);

    evaluator.mod_switch_to_inplace(a3_pt, ct_x3.parms_id());
    evaluator.multiply_plain_inplace(ct_x3, a3_pt);
    evaluator.rescale_to_next_inplace(ct_x3);

    evaluator.mod_switch_to_inplace(a1_pt, ct_x.parms_id());
    evaluator.multiply_plain_inplace(ct_x, a1_pt);
    evaluator.rescale_to_next_inplace(ct_x);

    evaluator.mod_switch_to_inplace(ct_x, ct_x5.parms_id());
    evaluator.mod_switch_to_inplace(ct_x3, ct_x5.parms_id());
    ct_x.scale() = ct_x5.scale();
    ct_x3.scale() = ct_x5.scale();
    evaluator.add(ct_x3, ct_x, ctdest);
    evaluator.add_inplace(ctdest, ct_x5);
    std::cout << "ct_dest  egale a " << std::endl;
    decrypt_decode_print(ctdest, encoder, decryptor);
}

void decrypt_decode_print(seal::Ciphertext &ct, seal::CKKSEncoder &encoder,
                          seal::Decryptor &decryptor) {
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