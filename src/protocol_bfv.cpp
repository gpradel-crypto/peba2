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
     * Protocol P execution using the BGV scheme.
     *
     */

    file_output_results << " The protocol P using the BFV scheme will be executed." << std::endl << std::endl;

    auto start_time_precomp = std::chrono::high_resolution_clock::now();

    /*
     *  Precomputation phase
     */
    file_output_results << "  ----------- Precomputation phase with BFV --------------" << std::endl;

    // Client side

    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 32768; // highest parameter 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 60)); //60 when using higher parameter

    //Slot dimension
    int quantisation_bits = 16; // cannot be higher than 25 with the highest SEAL parameters

    // Seal context set up, this checks if the parameters make sense
    file_output_results << "\t\t --- Information about computations ---" << std::endl;
    seal::SEALContext context(parms);
    int64_t scaling_factor = FindPowerOfTen(quantisation_bits);

    PrintParametersSEAL(context, file_output_results, 0, scaling_factor);

    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        std::string filename = "../keys/secret_bfv.key";
        if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
        {
            Stopwatch sw("Key already created, loading of the secret key", file_output_results, 1, Unit::microsecs);
            std::ifstream fs(filename, std::ios::binary);
            secret_key.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the secret key", file_output_results, 1, Unit::microsecs);
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
            Stopwatch sw("Key already created, loading of the public key", file_output_results, 1, Unit::microsecs);
            std::ifstream fs(filename, std::ios::binary);
            public_key.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the public key", file_output_results, 1, Unit::microsecs);
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
            Stopwatch sw("Key already created, loading of the relinearisation key", file_output_results, 1, Unit::microsecs);
            std::ifstream fs(filename, std::ios::binary);
            relin_keys.load(context, fs);
        }
        else {
            Stopwatch sw("Generation of the relinearisation key",
                         file_output_results, 1, Unit::millisecs);
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

    std::string path = "../pict_arrays/";

    std::ifstream reader;
    /*
     * For simplicity, as the encoded pictures are vectors of doubles, we first parse as vectors of doubles and then maps them to the integer space.
     */
    std::vector<std::vector<int64_t>> templates_int;
    std::vector<std::vector<double>> templates;
    std::vector<std::string> templates_files_name;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of integers", file_output_results, 1, Unit::microsecs);
        // int i=0; // for debugging
        for (const auto &file: std::filesystem::directory_iterator(path)) {
            //the if is only there to avoid to parse the ".gitkeep" file, more robust solutions would be preferable
            if (file.path().string().find(".gitkeep") == std::string::npos) {
                templates_files_name.push_back(file.path());
                // std::cout << "The template " << i << " is the file " << templates_files_name[i] << std::endl; // for debugging
                std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
                FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
                templates.push_back(tmp_vect);
                templates_int.push_back(MapDoublesToIntegers(tmp_vect, scaling_factor));
                // std::cout << "As double: ";
                // PrintVector(templates[i]);
                // std::cout << "After int mapping: ";
                // PrintVectorInt(templates_int[i]);
                // i++; // for debugging
            }
        }
        // PrintVector2Int(templates_int); // for debugging
    }

    // Encryption of the template
    {
        std::vector<seal::Plaintext> templates_pt;
        {
            Stopwatch sw("Encoding of the templates as plaintexts",
                         file_output_results, 1, Unit::microsecs);
            seal::Plaintext temp_pt;
            for (int i = 0; i < templates_int.size(); ++i) {
                encoder.encode(templates_int[i], temp_pt);
                templates_pt.push_back(temp_pt);
            }
        }
        std::vector<seal::Ciphertext> templates_ct;
        {
            Stopwatch sw("Encryption of the templates", file_output_results,
                         1, Unit::millisecs);
            seal::Ciphertext temp_ct;
            for (int i = 0; i < templates_pt.size(); ++i) {
                encryptor.encrypt(templates_pt[i], temp_ct);
                templates_ct.push_back(temp_ct);
            }
        }

        //Save the ciphertext in a file
        {
            Stopwatch sw("Serialisation of the encrypted templates",
                         file_output_results, templates_pt.size(), Unit::microsecs);
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
    EVP_PKEY_CTX *context_sig_server = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
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
    file_output_results << "  ----------- Computation phase with BFV --------------" << std::endl;
    auto start_time_comp = std::chrono::high_resolution_clock::now();

    //Client side

    //Generation of the sample
    std::string path_sample = "../pict_arrays/encoding_GPR.jpeg.data";
    // std::cout << "The sample is taken from " << path_sample << std::endl; // for debugging
    std::vector<double> sample = ParseEncoding(reader, path_sample);
    FillVectorUntilN(sample, encoder.slot_count(), 0.0);
    std::vector<int64_t> sample_int = MapDoublesToIntegers(sample, scaling_factor);

    // Encryption of the sample
    seal::Plaintext sample_pt;
    {
        Stopwatch sw("Encoding of the sample as a plaintext",
                     file_output_results, 1, Unit::microsecs);
        encoder.encode(sample_int, sample_pt);
    }
    seal::Ciphertext sample_ct;
    {
        Stopwatch sw("Encryption of the sample", file_output_results, 1, Unit::microsecs);
        encryptor.encrypt(sample_pt, sample_ct);
    }
    //Save the ciphertext in a file
    {
        Stopwatch sw("Serialisation of the sample", file_output_results, 1, Unit::microsecs);
        std::ofstream fs("../ciphertexts/sample_bfv.ct", std::ios::binary);
        sample_ct.save(fs);
    }

    // The Client sends the sample to the Server for the computations

    //Server side

    //loading of the template to compare with the sample
    seal::Ciphertext template_to_compare;
    std::srand(std::time(nullptr));
    int which_template = std::rand() % templates_int.size();
    std::cout << "The template that will be compared with the sample is " << templates_files_name[which_template] << std::endl; // for debugging
    {
        Stopwatch sw("Loading of the encrypted template", file_output_results, 1, Unit::microsecs);
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

    seal::Ciphertext euc_dist_ct;
    {
        Stopwatch sw("HE: Computation of the Euclidean distance (first part of the function f) between the template and the sample",file_output_results, 1, Unit::millisecs);
        enc_euclidean_dist_bfv(template_to_compare, sample_ct, euc_dist_ct, encoder,evaluator, gal_keys, relin_keys);
    }

    std::vector<double> bound(encoder.slot_count(), 0.3);
    int64_t squared_scaling_factor = scaling_factor*scaling_factor;
    std::vector<int64_t> bound_int = MapDoublesToIntegers(bound, squared_scaling_factor); //scaling factor is squared because the result of the Euclidean distance does not have the square root

    seal::Plaintext bound_pt;
    seal::Ciphertext bound_ct;
    {
        Stopwatch sw("Encoding and encryption of the bound.",
                     file_output_results, 1, Unit::microsecs);
        encoder.encode(bound_int, bound_pt);
        encryptor.encrypt(bound_pt, bound_ct);
    }
    {
        Stopwatch sw("HE: Computation of the subtraction of the euclidean distance by the bound.",
                     file_output_results, 1, Unit::microsecs);
        evaluator.mod_switch_to_inplace(bound_ct, euc_dist_ct.parms_id());
        evaluator.sub_inplace( bound_ct, euc_dist_ct);
    }


    //We use the difference between the bound by the Euclidean distance as the token
    // if the euclidean distance is lower than the bound, then the difference is positive. As a result, the output of the function g is also positive.
    // if the euclidean distance is equal or greater than the bound, then the difference is 0 or negative, as well as the output of the function g
    // when the verificateur receives back the token, it shall verify that the received token is a multiple of the random r generated by the server in the session
    // if not, then it refuses the authentication. AS a result, if it is equal to 0, although it should accept the match, the server cannot accept the authentication as
    // this would be a easy way to break the protocol (the client simply sends back an encrypted 0 and that's it)

    auto end_time_function_f = std::chrono::high_resolution_clock::now();
    auto duration_function_f = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_function_f - start_time_function_f);

    file_output_results << "The function f has lasted " << duration_function_f.count()/1000.0 << " seconds." << std::endl;

    auto start_time_function_g = std::chrono::high_resolution_clock::now();
    // Server generates the random number Tau
    std::vector<int64_t> tau (128, RandomLongInt());
    seal::Plaintext tau_pt;
    {
        Stopwatch sw("Generation of tau and encoding.",file_output_results, 1, Unit::microsecs);
        encoder.encode(tau, tau_pt);
        // Server applies g function
        // evaluator.mod_switch_to_inplace(tau_pt, euc_dist_ct.parms_id());
    }
    {
        Stopwatch sw("HE: Computation of the multiplication in g", file_output_results,
                     1, Unit::microsecs);
        evaluator.multiply_plain_inplace(bound_ct, tau_pt);
    }
    file_output_results << "Calculation of the token y completed." << std::endl;
    // Save the token y encrypted in a file to send it to client
    {
        Stopwatch sw("Serialisation of the token", file_output_results,
                     1, Unit::microsecs);
        std::ofstream fs("../ciphertexts/token_bfv.ct", std::ios::binary);
        bound_ct.save(fs);
    }

    auto end_time_function_g = std::chrono::high_resolution_clock::now();
    auto duration_function_g = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_function_g - start_time_function_g);

    file_output_results << "The function g has lasted " << duration_function_g.count() << " milliseconds." << std::endl;

    auto start_time_signature_s = std::chrono::high_resolution_clock::now();

    // Now with BFV, contrary to CKKS, computations are exact; thus, we are supposed to compute the signature on the clear tau and clear 0
    // However, because we don't compute the comparison function over the Euclidean distance and the bound
    // we shall compute the signature over the encrypted tau again
    auto start_time_creation_msg_token = std::chrono::high_resolution_clock::now();
    std::vector<char> v_msg_token = FromFileToVect("../ciphertexts/token_bfv.ct");
    auto end_time_creation_msg_token = std::chrono::high_resolution_clock::now();
    auto duration_creation_msg_token = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_creation_msg_token - start_time_creation_msg_token);
    file_output_results << "The transformation from token file to message for signature has taken " << duration_creation_msg_token.count() << " milliseconds." << std::endl;


    unsigned char msg_token[v_msg_token.size()];
    {
        Stopwatch sw("Token as a message for signature", file_output_results,
                     1, Unit::microsecs);
        for (int i = 0; i < v_msg_token.size(); ++i) {
            msg_token[i] = v_msg_token[i];
        }
    }
    // std::vector<double> zero;
    // FillVectorUntilN(zero, encoder.slot_count(), 0.0);
    // std::vector<int64_t> zero_int = MapDoublesToIntegers(zero, scaling_factor);
    // seal::Plaintext zero_pt_in, zero_pt_out;
    // seal::Ciphertext zero_ct;
    // std::vector<int64_t> zero_decrypted;
    // encoder.encode(zero_int, zero_pt_in);
    // encryptor.encrypt(zero_pt_in, zero_ct);
    // decryptor.decrypt(zero_ct, zero_pt_out);
    // encoder.decode(zero_pt_out, zero_decrypted);

    // unsigned char msg_zero[encoder.slot_count()];
    // memset(msg_zero,0,encoder.slot_count());
    uint8_t *token_sig = NULL;
    // uint8_t *zero_sig = NULL;
    size_t token_sig_length = 0;
    // size_t zero_sig_length = 0;
    //signature of the token by the server
    EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_server);
    EVP_MD_CTX_init(context_sig);
    if (EVP_DigestSignInit(context_sig, &context_sig_server, NULL, NULL,
                           sig_key_server) != 1) {
        perror("Problem with initialisation of the signature.");
        abort();
    }

    // Signature of the token
    if (EVP_DigestSign(context_sig, token_sig, &token_sig_length, msg_token,
                       sizeof(msg_token)) != 1) {
        perror("Signature cannot be done.");
        abort();
    }
    token_sig = (uint8_t *) malloc(token_sig_length * sizeof(uint8_t));
    if (EVP_DigestSign(context_sig, token_sig, &token_sig_length, msg_token,
                       sizeof(msg_token)) != 1) {
        perror("Signature cannot be done.");
        abort();
    }

    // // Signature of Zero
    // // if (EVP_DigestSign(context_sig, zero_sig, &zero_sig_length, msg_zero,
    //                    // sizeof(msg_zero)) != 1) {
    //     // perror("Signature cannot be done.");
    //     // abort();
    //                    }
    // // zero_sig = (uint8_t *) malloc(zero_sig_length * sizeof(uint8_t));
    // // if (EVP_DigestSign(context_sig, zero_sig, &zero_sig_length, msg_zero,
    //                    // sizeof(msg_zero)) != 1) {
    //     // perror("Signature cannot be done.");
    //     // abort();
    //                    // }

    EVP_MD_CTX_free(context_sig);

    file_output_results << "Signature by the Server done." << std::endl;

    auto end_time_signature_s = std::chrono::high_resolution_clock::now();
    auto duration_signature_s = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_signature_s - start_time_signature_s);

    file_output_results << "The signature by S has taken " << duration_signature_s.count() << " milliseconds." << std::endl;

    //Server sends to Client the encrypted token and its signature
    //Normally, the Client decrypts the token to verify the signatures on clear tau and clear 0
    //But currently, the signature of the token is still done on the encrypted version, although it should be done
    //on the clear version

    seal::Plaintext token_pt;
    std::vector<int64_t> token;
    {
        Stopwatch sw("HE: Decryption and decoding of the token.",
                     file_output_results, 1, Unit::microsecs);
        decryptor.decrypt(bound_ct, token_pt);
        encoder.decode(token_pt, token);
    }

    auto start_time_verif_sig = std::chrono::high_resolution_clock::now();

    //Client receives them, verifies the signatures and decrypts the token
    //Verification of the signature, if wrong then quit
    EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_server);
    EVP_MD_CTX_init(context_verif);

    if (EVP_DigestVerifyInit(context_verif, &context_sig_server, NULL, NULL,
                             sig_key_server) != 1) {
        perror("Problem with initialisation of the verification.");
        abort();
    }

    //Verification of the token signature
    // if ((EVP_DigestVerify(context_verif, token_sig, token_sig_length, msg_token,
    // sizeof(msg_token)) != 1) || (EVP_DigestVerify(context_verif, zero_sig, zero_sig_length, msg_zero,
    // sizeof(msg_zero)) != 1)) {
    if (EVP_DigestVerify(context_verif, token_sig, token_sig_length, msg_token,sizeof(msg_token)) != 1) {
        perror("Verification of the signature cannot be done.");
        abort();
    }

    // Verification of the zero signature on the decrypted token

    // if (EVP_DigestVerify(context_verif, zero_sig, zero_sig_length, msg_zero,sizeof(msg_zero)) != 1) {
        // perror("Verification of the signature cannot be done.");
        // abort();
    // }

    //No longer need of the signature items for the client
    EVP_MD_CTX_free(context_verif);
    EVP_PKEY_free(sig_key_server);
    OPENSSL_free(token_sig);

    file_output_results << "Signature verified by the Client." << std::endl;
    auto end_time_verif_sig = std::chrono::high_resolution_clock::now();
    auto duration_verif_sig = std::chrono::duration_cast<std::chrono::microseconds>(end_time_verif_sig - start_time_verif_sig);
    file_output_results << "The verification of the signature by S has taken " << duration_verif_sig.count() << " microseconds." << std::endl;


    //To compare with the true result
    int64_t euc_dist_true = euclidean_distance_int(templates_int[which_template], sample_int);
    bool b = false;
    if (euc_dist_true < bound_int[0])
        b = true;
    int64_t token_true = (bound_int[0] - euc_dist_true) * tau[0];
    file_output_results << "The token shall be about " << token_true << " and thus, the authentication shall ";
    if (b == false)
        file_output_results << "fail." << std::endl;
    else
        file_output_results << "succeed." << std::endl;


    if (token[0] == 0) {
        file_output_results << "The authentication was unsuccessful and the token " << token[0] << " is not usable to access to the desired service." << std::endl;
    }
    else if (token[0]%tau[0] != 0) {
        file_output_results << "The authentication was unsuccessful and the token " << token[0] << " is not usable to access to the desired service." << std::endl;
    } else if (token[0] < 0) {
        file_output_results << "The authentication was unsuccessful and the token " << token[0] << " is not usable to access to the desired service." << std::endl;
    }
    else {
        file_output_results << "The authentication was successful and the token " << token[0] << " is usable to access to the desired service." << std::endl;
    }

    auto end_time_comp = std::chrono::high_resolution_clock::now();
    auto duration_comp = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_comp - start_time_comp);
    file_output_results << std::endl << "The computation phase has taken " << duration_comp.count()/1000.0 << " seconds." << std::endl << std::endl;

    /*
    * END OF THE PROTOCOL
    */
}