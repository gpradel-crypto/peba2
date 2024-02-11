//
// Created by gpra on 29/11/23.
//
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <seal/seal.h>
#include "homomorphic_math.h"
#include "plain_math.h"
#include "utilities.h"
#include "protocol_bfv.h"

void protocol_p_bfv(std::ofstream &file_output_results){
    /*
     *
     * Protocol P execution !
     *
     */

    file_output_results << " The protocol P using the BFV scheme will be executed." << std::endl << std::endl;

    auto start_time_precomp = std::chrono::high_resolution_clock::now();

    /*
     *  Precomputation phase
     */
    file_output_results << "  ----------- Precomputation phase with BFV --------------"
                        << std::endl;

    // Client side

    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    // parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 60));
    // const std::vector<int> bitsizes = {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60};

    //Slot dimension
    const size_t dimension = poly_modulus_degree / 2;
    //scale for encoding
    // int power_of_scale = 40; // put 30 if the other parameters are chosen
    // double scale = pow(2.0, power_of_scale);
    int quantisation_bits = 25; // cannot be higher than 25 with the highest SEAL parameters

    // Seal context set up, this checks if the parameters make sense
    file_output_results << "\t\t --- Information about computations ---"
                        << std::endl;
    seal::SEALContext context(parms);
    // auto &context_data = *context.key_context_data();
    // double rescaling_factor = context.key_context_data()->parms().plain_modulus().value()/pow(2,quantisation_bits);
    int64_t scaling_factor = FindPowerOfTen(quantisation_bits);

    // PrintParametersSEAL(context, file_output_results, 0, rescaling_factor_int);
    PrintParametersSEAL(context, file_output_results, 0, scaling_factor);

    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        std::string filename = "../keys/secret_bfv.key";
        if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
        {
            Stopwatch sw("Key already created, loading of the secret key", file_output_results, 1, Unit::millisecs);
            std::ifstream fs(filename, std::ios::binary);
            secret_key.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the secret key", file_output_results, 1, Unit::millisecs);
            std::ofstream fs(filename, std::ios::binary);
            secret_key = keygen.secret_key();
            secret_key.save(fs);
        }
    }

    seal::PublicKey public_key;
    {
        std::string filename = "../keys/public_bfv.key";
        if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
        {
            Stopwatch sw("Key already created, loading of the public key", file_output_results, 1, Unit::millisecs);
            std::ifstream fs(filename, std::ios::binary);
            public_key.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the public key", file_output_results, 1, Unit::millisecs);
            keygen.create_public_key(public_key);
            std::ofstream fs(filename, std::ios::binary);
            public_key.save(fs);
        }
    }

    seal::RelinKeys relin_keys;
    {
        std::string filename = "../keys/relin_bfv.key";
        if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
        {
            Stopwatch sw("Key already created, loading of the relinearisation key", file_output_results, 1, Unit::millisecs);
            std::ifstream fs(filename, std::ios::binary);
            relin_keys.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the relinearisation key",
                         file_output_results, 1, Unit::secs);
            keygen.create_relin_keys(relin_keys);
            std::ofstream fs(filename, std::ios::binary);
            relin_keys.save(fs);
        }
    }

    seal::GaloisKeys gal_keys;
    {
        std::string filename = "../keys/galois_bfv.key";
        if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
        {
            Stopwatch sw("Key already created, loading of the galois keys", file_output_results, 1, Unit::secs);
            std::ifstream fs(filename, std::ios::binary);
            gal_keys.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the galois keys", file_output_results, 1, Unit::secs);
            keygen.create_galois_keys(gal_keys);
            std::ofstream fs(filename, std::ios::binary);
            gal_keys.save(fs);
        }
    }

    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::BatchEncoder encoder(context);

    auto end_time_params = std::chrono::high_resolution_clock::now();
    auto duration_params = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_params - start_time_params);
    file_output_results << "Parameters and keys with BFV were set in " << duration_params.count()/1000.0 << " seconds." << std::endl;

    size_t slot_count = encoder.slot_count();
    size_t row_size = slot_count / 2;

    std::string path = "../pict_arrays/";

    std::ifstream reader;
    /*
     * For simplicity, as the encoded pictures are vectors of doubles, we first parse as vectors of doubles and then maps to the integer space.
     */
    std::vector<std::vector<int64_t>> templates_int;
    std::vector<std::string> templates_files_name;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of integers", file_output_results, 1, Unit::microsecs);
        int i=0; // for debugging
        for (const auto &file: std::filesystem::directory_iterator(path)) {
            //the if is only there to avoid to parse the ".gitkeep" file, more robust solutions would be preferable
            if (file.path().string().find(".gitkeep") == std::string::npos) {
                templates_files_name.push_back(file.path());
                std::cout << "The template " << i << " is the file " << templates_files_name[i] << std::endl; // for debugging
                i++; // for debugging
                std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
                FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
                templates_int.push_back(MapDoublesToIntegers(tmp_vect, scaling_factor, quantisation_bits));
            }
        }
        // PrintVector2Int(templates_int); // for debugging
    }

    // Encryption of the template
    {
        std::vector<seal::Plaintext> templates_pt;
        {
            Stopwatch sw("Encoding of the templates as plaintexts",
                         file_output_results, 1, Unit::secs);
            seal::Plaintext temp_pt;
            for (int i = 0; i < templates_int.size(); ++i) {
                encoder.encode(templates_int[i], temp_pt);
                templates_pt.push_back(temp_pt);
            }
        }
        std::vector<seal::Ciphertext> templates_ct;
        {
            Stopwatch sw("Encryption of the templates", file_output_results,
                         1, Unit::secs);
            seal::Ciphertext temp_ct;
            for (int i = 0; i < templates_pt.size(); ++i) {
                encryptor.encrypt(templates_pt[i], temp_ct);
                templates_ct.push_back(temp_ct);
            }
        }
        decrypt_decode_print_bfv(templates_ct[0], encoder, decryptor, "At the beginning of the function f, template[0] is equal to:"); // for debugging
        decrypt_decode_print_bfv(templates_ct[1], encoder, decryptor, "At the beginning of the function f, template[1] is equal to:"); // for debugging
        decrypt_decode_print_bfv(templates_ct[2], encoder, decryptor, "At the beginning of the function f, template[2] is equal to:"); // for debugging
        //Save the ciphertext in a file
        {
            Stopwatch sw("Serialisation of the encrypted templates",
                         file_output_results, templates_pt.size(), Unit::millisecs);
            for (int i = 0; i < templates_ct.size(); ++i) {
                std::string file_name_ct = "../ciphertexts/template_bfv";
                file_name_ct.append(std::to_string(i));
                file_name_ct.append(".ct");
                std::ofstream fs(file_name_ct, std::ios::binary);
                templates_ct[i].save(fs);
            }
        }
    }
    // Server side
    // Create of the signature key of the server
    EVP_PKEY *sig_key_server = NULL;
    EVP_PKEY_CTX *context_sig_server = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,
                                                           NULL);
    EVP_PKEY_keygen_init(context_sig_server);
    EVP_PKEY_keygen(context_sig_server, &sig_key_server);
    {
        Stopwatch sw("Generation of the public key for signature of the server",
                     file_output_results, 1, Unit::microsecs);
        FILE *file;
        file = fopen("../keys/signature_server_pub_bfv.key", "wb");
        if (file == NULL) {
            perror("Error opening file to save public signature key.");
            abort();
        }
        PEM_write_PUBKEY(file, sig_key_server);
        fclose(file);
    }
    {
        Stopwatch sw(
                "Generation of the private key for signature of the server",
                file_output_results, 1, Unit::microsecs);
        FILE *file;
        file = fopen("../keys/signature_server_priv_bfv.key", "wb");
        if (file == NULL) {
            perror("Error opening file to save private signature key.");
            abort();
        }
        PEM_write_PrivateKey(file, sig_key_server, NULL, NULL, 0, NULL, NULL);
        fclose(file);
    }

    //Client sends the template encrypted to the server

    //Server side

    auto end_time_precomp = std::chrono::high_resolution_clock::now();
    auto duration_precomp = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_precomp - start_time_precomp);
    file_output_results << std::endl << "The precomputation phase with BFV has taken " << duration_precomp.count()/1000.0 << " seconds." << std::endl << std::endl;

    /*
     * Computation phase
     *
     */
    file_output_results << "  ----------- Computation phase with BFV --------------"
                        << std::endl;
    auto start_time_comp = std::chrono::high_resolution_clock::now();

    //Client side

    //Generation of the sample
    std::string path_sample = "../pict_arrays/encoding_GPR.jpeg.data";
    std::cout << "The sample is taken from " << path_sample << std::endl; // for debugging
    std::vector<double> sample = ParseEncoding(reader, path_sample);
    FillVectorUntilN(sample, encoder.slot_count(), 0.0);
    std::vector<int64_t> sample_int = MapDoublesToIntegers(sample, scaling_factor, quantisation_bits);

    // Encryption of the sample
    seal::Plaintext sample_pt;
    {
        Stopwatch sw("Encoding of the sample as a plaintext",
                     file_output_results, 1, Unit::millisecs);
        encoder.encode(sample_int, sample_pt);
    }
    seal::Ciphertext sample_ct;
    {
        Stopwatch sw("Encryption of the sample", file_output_results, 1, Unit::millisecs);
        encryptor.encrypt(sample_pt, sample_ct);
    }
    //Save the ciphertext in a file
    {
        Stopwatch sw("Serialisation of the sample", file_output_results, 1, Unit::millisecs);
        std::ofstream fs("../ciphertexts/sample_bfv.ct", std::ios::binary);
        sample_ct.save(fs);
    }

    // The Client sends the sample to the Server for the computations

    //Server side

    //loading of the template to compare with the sample
    seal::Ciphertext template_to_compare;
    // std::srand(std::time(nullptr));
    // int which_template = std::rand() % 3;
    int which_template = 2;
    std::cout << "The template that will be compared with the sample is " << templates_files_name[which_template] << std::endl; // for debugging
    {
        Stopwatch sw("Loading of the encrypted template", file_output_results, 1, Unit::millisecs);
        std::string file_name_template_to_compare = "../ciphertexts/template_bfv";
        file_name_template_to_compare.append(std::to_string(which_template));
        file_name_template_to_compare.append(".ct");
        std::ifstream fitl(file_name_template_to_compare, std::ios::binary);
        if (fitl) {
            std::stringstream buffer;
            buffer << fitl.rdbuf();
            fitl.close();
            template_to_compare.load(context, buffer);
        }
    }

    // To measure the time of the f function
    auto start_time_function_f = std::chrono::high_resolution_clock::now();


    decrypt_decode_print_bfv(sample_ct, encoder, decryptor, "At the beginning of the function f, sample_bfv is equal to:");
    decrypt_decode_print_bfv(template_to_compare, encoder, decryptor, "At the beginning of the function f, template_to_compare is equal to:");

    std::cout << " Noise budget in sample_bfv.ct before Euclidean distance: " << decryptor.invariant_noise_budget(sample_ct) << " bits" << std::endl;

    seal::Ciphertext euc_dist_ct;
    {
        Stopwatch sw(
                "HE: Computation of the Euclidean distance (first part of the function f) between the template and the sample",
                file_output_results, 1, Unit::secs);
        enc_euclidean_dist_bfv(template_to_compare, sample_ct, euc_dist_ct, encoder,
                           evaluator, gal_keys, relin_keys, decryptor);
    }
    std::cout << " Noise budget in euc__dist_ct after Euclidean distance between sample and template: " << decryptor.invariant_noise_budget(euc_dist_ct) << " bits" << std::endl;
    decrypt_decode_print_bfv(euc_dist_ct, encoder, decryptor, "The squared Euclidean distance is equal to:");
    std::cout << std::endl << "The Euclidean distance shall be equal to: " << euclidean_distance_int(templates_int[1], templates_int[which_template]) << std::endl;

    std::vector<double> bound(encoder.slot_count(), 0.3);
    // std::cout << "The bound in double is: " << std::endl; // for debugging
    // PrintVector(bound); // for debugging
    std::vector<int64_t> bound_int = MapDoublesToIntegers(bound, scaling_factor, quantisation_bits);
    // std::cout << "The bound in uint64_t after mapping is: " << std::endl; // for debugging
    PrintVectorIntUntilN(bound_int, 128); // for debugging
    //face_recognition library python has a 0.6 bound for the euclidean distance
    //here we have the square of the distance, and 0.6^2 = 0.36
    //we decided to be a bit more strict and compare with 0.3
    seal::Plaintext bound_pt;
    seal::Ciphertext bound_ct;
    {
        Stopwatch sw("Encoding and encryption of the bound.",
                     file_output_results, 1, Unit::millisecs);
        encoder.encode(bound_int, bound_pt);
        encryptor.encrypt(bound_pt, bound_ct);
    }
    {
        Stopwatch sw("HE: Computation of the subtraction of the euclidean distance by the bound.",
                     file_output_results, 1, Unit::millisecs);
        evaluator.mod_switch_to_inplace(bound_ct, euc_dist_ct.parms_id());
        evaluator.sub_inplace( euc_dist_ct, bound_ct);
    }
    decrypt_decode_print_bfv(euc_dist_ct, encoder, decryptor, "The approximate subtraction of the Euclidean distance by the bound is equal to:");


    // //Based on the difference between the euclidean distance and the bound, we generate an approximation
    // //of the comparison function
    // //we use, from the Asiacrypt 2020 paper, composition of g3 o f4 o f3
    //
    // seal::Ciphertext b_approx_ct, tmp_approx_ct;
    // enc_g3(bound_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    // enc_f4(b_approx_ct, tmp_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    // enc_f3(tmp_approx_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    // enc_final_approx_inplace(b_approx_ct, encoder, decryptor, evaluator, scale);
    //
    //
    // auto end_time_function_f = std::chrono::high_resolution_clock::now();
    // auto duration_function_f = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_function_f - start_time_function_f);
    //
    // file_output_results << "The function f has lasted " << duration_function_f.count()/1000.0 << " seconds." << std::endl;
    //
    // auto start_time_function_g = std::chrono::high_resolution_clock::now();
    // // Server generates the random number Tau
    // double tau = abs(RandomDouble());
    //
    // // Server creates the plaintext for Tau
    // seal::Plaintext tau_pt;
    // {
    //     Stopwatch sw(
    //             "Generation of tau, encoding and modulus switch for computation.",
    //             file_output_results, 1, Unit::microsecs);
    //     encoder.encode(tau, scale, tau_pt);
    //     // Server applies g function
    //     evaluator.mod_switch_to_inplace(tau_pt, b_approx_ct.parms_id());
    // }
    // {
    //     Stopwatch sw("HE: Computation of the multiplication in g", file_output_results,
    //                  1, Unit::microsecs);
    //     evaluator.multiply_plain_inplace(b_approx_ct, tau_pt);
    // }
    // file_output_results << "Calculation of the token y completed." << std::endl;
    // // Save the token y encrypted in a file to send it to client
    // {
    //     std::ofstream fs("../ciphertexts/token.ct", std::ios::binary);
    //     b_approx_ct.save(fs);
    // }
    //
    // auto end_time_function_g = std::chrono::high_resolution_clock::now();
    // auto duration_function_g = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_function_g - start_time_function_g);
    //
    // file_output_results << "The function g has lasted " << duration_function_g.count() << " milliseconds." << std::endl;
    //
    // auto start_time_signature_s = std::chrono::high_resolution_clock::now();
    //
    // //Write tau as a char* for signature.
    // std::vector<char> v_msg_token = FromFileToVect("../ciphertexts/token.ct");
    // unsigned char msg_token[v_msg_token.size()];
    // for (int i = 0; i < v_msg_token.size(); ++i) {
    //     msg_token[i] = v_msg_token[i];
    // }
    // uint8_t *token_sig = NULL;
    // size_t token_sig_length = 0;
    // //signature of the token by the server
    // EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
    // EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_server);
    // EVP_MD_CTX_init(context_sig);
    // if (EVP_DigestSignInit(context_sig, &context_sig_server, NULL, NULL,
    //                        sig_key_server) != 1) {
    //     perror("Problem with initialisation of the signature.");
    //     abort();
    // }
    //
    // if (EVP_DigestSign(context_sig, token_sig, &token_sig_length, msg_token,
    //                    sizeof(msg_token)) != 1) {
    //     perror("Signature cannot be done.");
    //     abort();
    // }
    // token_sig = (uint8_t *) malloc(token_sig_length * sizeof(uint8_t));
    // if (EVP_DigestSign(context_sig, token_sig, &token_sig_length, msg_token,
    //                    sizeof(msg_token)) != 1) {
    //     perror("Signature cannot be done.");
    //     abort();
    // }
    // EVP_MD_CTX_free(context_sig);
    //
    // file_output_results << "Signature by the Server done." << std::endl;
    //
    // auto end_time_signature_s = std::chrono::high_resolution_clock::now();
    // auto duration_signature_s = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_signature_s - start_time_signature_s);
    //
    // file_output_results << "The signature by S has taken " << duration_signature_s.count() << " milliseconds." << std::endl;
    //
    // //Server sends to Client the token and its signature
    //
    // auto start_time_verif_sig = std::chrono::high_resolution_clock::now();
    //
    // //Client receives them, verifies the signature and decrypts the token
    // //Verification of the signature, if wrong then quit
    // EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
    // EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_server);
    // EVP_MD_CTX_init(context_verif);
    //
    // if (EVP_DigestVerifyInit(context_verif, &context_sig_server, NULL, NULL,
    //                          sig_key_server) != 1) {
    //     perror("Problem with initialisation of the verification.");
    //     abort();
    // }
    // if (EVP_DigestVerify(context_verif, token_sig, token_sig_length, msg_token,
    //                      sizeof(msg_token)) != 1) {
    //     perror("Verification of the signature cannot be done.");
    //     abort();
    // }
    //
    // //No longer need of the signature items for the client
    // EVP_MD_CTX_free(context_verif);
    // EVP_PKEY_free(sig_key_server);
    // OPENSSL_free(token_sig);
    //
    // file_output_results << "Signature verified by the Client." << std::endl;
    // auto end_time_verif_sig = std::chrono::high_resolution_clock::now();
    // auto duration_verif_sig = std::chrono::duration_cast<std::chrono::microseconds>(end_time_verif_sig - start_time_verif_sig);
    // file_output_results << "The verification of the signature by S has taken " << duration_verif_sig.count() << " microseconds." << std::endl;
    //
    // seal::Plaintext token_pt;
    // std::vector<double> token;
    // {
    //     Stopwatch sw("HE: Decryption and decoding of the token.",
    //                  file_output_results, 1, Unit::microsecs);
    //     decryptor.decrypt(b_approx_ct, token_pt);
    //     encoder.decode(token_pt, token);
    // }
    //
    //
    // //To compare with the true result
    // double euc_dist_true = euclidean_distance(templates[which_template], sample);
    // double b = 0.0;
    // if (euc_dist_true < bound[0])
    //     b = 1.0;
    // double token_true = b * tau;
    // file_output_results << "The token shall be about " << token_true << " and thus, the authentication shall ";
    // if (b == 0.0)
    //     file_output_results << "fail." << std::endl;
    // else
    //     file_output_results << "succeed." << std::endl;
    //
    //
    //
    // //Given it is an approximate calculus, we accepted the following error in the computation for the acceptance of the token
    // double error_accepted = 0.001;
    //
    // if ((token[0] < (tau / 2.0)+error_accepted) && (token[0] > -error_accepted)) {
    //     file_output_results
    //             << "The authentication was unsuccessful and the token "
    //             << token[0]
    //             << " is not usable to access to the desired service."
    //             << std::endl;
    // } else {
    //     file_output_results
    //             << "The authentication was successful and the token "
    //             << token[0] << " is usable to access to the desired service."
    //             << std::endl;
    //
    // }
    //
    // auto end_time_comp = std::chrono::high_resolution_clock::now();
    // auto duration_comp = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_comp - start_time_comp);
    // file_output_results << std::endl << "The computation phase has taken " << duration_comp.count()/1000.0 << " seconds." << std::endl << std::endl;
    //
    // /*
    // * END OF THE PROTOCOL
    // */
}