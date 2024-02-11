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
#include "protocol_ckks.h"

void protocol_p(std::ofstream &file_output_results){
    /*
     *
     * Protocol P execution !
     *
     */

    file_output_results << " The protocol P will be executed." << std::endl << std::endl;

    auto start_time_precomp = std::chrono::high_resolution_clock::now();

    /*
     *  Precomputation phase
     */
    file_output_results << "  ----------- Precomputation phase --------------"
                        << std::endl;

    // Client side

    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree,
                                                       {60, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 60}));
    // use parameters below to have more multiplicative depth but less precision due to the scale being less
//    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, {60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,30,30,30,30,30,30,30,30,30,30,30,30, 60}));

    const std::vector<int> bitsizes = {60, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       60};
//    const std::vector<int> bitsizes = {60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,30,30,30,30,30,30,30,30,30,30,30,30, 60};

    //Slot dimension
    const size_t dimension = poly_modulus_degree / 2;
    //scale for encoding
    int power_of_scale = 40; // put 30 if the other parameters are chosen
    double scale = pow(2.0, power_of_scale);

    // Seal context set up, this checks if the parameters make sense
    file_output_results << "\t\t --- Information about computations ---"
                        << std::endl;
    seal::SEALContext context(parms);
    PrintParametersSEAL(context, file_output_results, power_of_scale,0.0);


    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        std::string filename = "../keys/secret.key";
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
        std::string filename = "../keys/public.key";
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
        std::string filename = "../keys/relin.key";
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
        std::string filename = "../keys/galois.key";
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
    seal::CKKSEncoder encoder(context);

    auto end_time_params = std::chrono::high_resolution_clock::now();
    auto duration_params = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_params - start_time_params);
    file_output_results << "Parameters and keys were set in " << duration_params.count()/1000.0 << " seconds." << std::endl;

    std::string path = "../pict_arrays/";

    std::ifstream reader;
    std::vector<std::vector<double>> templates;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of doubles", file_output_results, 1, Unit::microsecs);
        int i=0;
        for (const auto &file: std::filesystem::directory_iterator(path)) {
            //the if is only there to avoid to parse the ".gitkeep" file, more robust solutions would be preferable
            if (file.path().string().find(".gitkeep") == std::string::npos) {
                std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
                FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
                templates.push_back(tmp_vect);
            }
        }
    }

    // Encryption of the template
    {
        std::vector<seal::Plaintext> templates_pt;
        {
            Stopwatch sw("Encoding of the templates as plaintexts",
                         file_output_results, 1, Unit::secs);
            seal::Plaintext temp_pt;
            for (int i = 0; i < templates.size(); ++i) {
                encoder.encode(templates[i], scale, temp_pt);
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
        //Save the ciphertext in a file
        {
            Stopwatch sw("Serialisation of the encrypted templates",
                         file_output_results, templates_pt.size(), Unit::millisecs);
            for (int i = 0; i < templates_ct.size(); ++i) {
                std::string file_name_ct = "../ciphertexts/template";
                file_name_ct.append(std::to_string(i + 1));
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
        file = fopen("../keys/signature_server_pub.key", "wb");
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
        file = fopen("../keys/signature_server_priv.key", "wb");
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
    file_output_results << std::endl << "The precomputation phase has taken " << duration_precomp.count()/1000.0 << " seconds." << std::endl << std::endl;

    /*
     * Computation phase
     *
     */
    file_output_results << "  ----------- Computation phase --------------"
                        << std::endl;
    auto start_time_comp = std::chrono::high_resolution_clock::now();

    //Client side

    //Generation of the sample
    std::string path_sample = "../pict_arrays/encoding_GPR.jpeg.data";
    std::vector<double> sample = ParseEncoding(reader, path_sample);
    FillVectorUntilN(sample, encoder.slot_count(), 0.0);

    // Encryption of the sample
    seal::Plaintext sample_pt;
    {
        Stopwatch sw("Encoding of the sample as a plaintext",
                     file_output_results, 1, Unit::millisecs);
        encoder.encode(sample, scale, sample_pt);
    }
    seal::Ciphertext sample_ct;
    {
        Stopwatch sw("Encryption of the sample", file_output_results, 1, Unit::millisecs);
        encryptor.encrypt(sample_pt, sample_ct);
    }
    //Save the ciphertext in a file
    {
        Stopwatch sw("Serialisation of the sample", file_output_results, 1, Unit::millisecs);
        std::ofstream fs("../ciphertexts/sample.ct", std::ios::binary);
        sample_ct.save(fs);
    }

    // The Client sends the sample to the Server for the computations

    //Server side

    //loading of the template to compare with the sample
    seal::Ciphertext template_to_compare;
    int which_template = 1;
    {
        Stopwatch sw("Loading of the encrypted template", file_output_results, 1, Unit::millisecs);
        std::string file_name_template_to_compare = "../ciphertexts/template";
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
        Stopwatch sw(
                "HE: Computation of the euclidean distance (first part of the function f) between the template and the sample",
                file_output_results, 1, Unit::secs);
        enc_euclidean_dist(template_to_compare, sample_ct, euc_dist_ct, encoder,
                           evaluator, gal_keys, relin_keys, scale);
    }

    decrypt_decode_print(euc_dist_ct, encoder, decryptor, "The approximate euclidean distance is equal to:");

    /*
     * Choice of a bound, and computation of the comparison between the euclidean distance and this bound
     * We use the technique from Cheon et al. in "Efficient Homomorphic Comparison Methods with Optimal Complexity"
     * Asiacrypt 2020
     *              {1 if a > b
     * comp(a,b) =  {1/2 if a = b
     *              {0 if a < b
     */
    std::vector<double> bound(dimension, 0.3);
    //face_recognition library python has a 0.6 bound for the euclidean distance
    //here we have the square of the distance, and 0.6^2 = 0.36
    //we decided to be a bit more strict and compare with 0.3
    seal::Plaintext bound_pt;
    seal::Ciphertext bound_ct;
    {
        Stopwatch sw("Encoding and encryption of the bound.",
                     file_output_results, 1, Unit::millisecs);
        encoder.encode(bound, scale, bound_pt);
        encryptor.encrypt(bound_pt, bound_ct);
    }
    {
        Stopwatch sw("HE: Computation of the subtraction of the bound by the euclidean distance.",
                     file_output_results, 1, Unit::millisecs);
        evaluator.mod_switch_to_inplace(bound_ct, euc_dist_ct.parms_id());
        euc_dist_ct.scale() = scale;
        evaluator.sub_inplace( bound_ct, euc_dist_ct);
    }
    decrypt_decode_print(bound_ct, encoder, decryptor, "The approximate subtraction of the bound by euc dist is equal to:");


    //Based on the difference between the euclidean distance and the bound, we generate an approximation
    //of the comparison function
    //we use, from the Asiacrypt 2020 paper, composition of g3 o f4 o f3

    seal::Ciphertext b_approx_ct, tmp_approx_ct;
    enc_g3(bound_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    enc_f4(b_approx_ct, tmp_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    enc_f3(tmp_approx_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
    enc_final_approx_inplace(b_approx_ct, encoder, decryptor, evaluator, scale);


    auto end_time_function_f = std::chrono::high_resolution_clock::now();
    auto duration_function_f = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_function_f - start_time_function_f);

    file_output_results << "The function f has lasted " << duration_function_f.count()/1000.0 << " seconds." << std::endl;

    auto start_time_function_g = std::chrono::high_resolution_clock::now();
    // Server generates the random number Tau
    double tau = abs(RandomDouble());

    // Server creates the plaintext for Tau
    seal::Plaintext tau_pt;
    {
        Stopwatch sw(
                "Generation of tau, encoding and modulus switch for computation.",
                file_output_results, 1, Unit::microsecs);
        encoder.encode(tau, scale, tau_pt);
        // Server applies g function
        evaluator.mod_switch_to_inplace(tau_pt, b_approx_ct.parms_id());
    }
    {
        Stopwatch sw("HE: Computation of the multiplication in g", file_output_results,
                     1, Unit::microsecs);
        evaluator.multiply_plain_inplace(b_approx_ct, tau_pt);
    }
    file_output_results << "Calculation of the token y completed." << std::endl;
    // Save the token y encrypted in a file to send it to client
    {
        std::ofstream fs("../ciphertexts/token.ct", std::ios::binary);
        b_approx_ct.save(fs);
    }

    auto end_time_function_g = std::chrono::high_resolution_clock::now();
    auto duration_function_g = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_function_g - start_time_function_g);

    file_output_results << "The function g has lasted " << duration_function_g.count() << " milliseconds." << std::endl;

    auto start_time_signature_s = std::chrono::high_resolution_clock::now();

    //Write tau as a char* for signature.
    std::vector<char> v_msg_token = FromFileToVect("../ciphertexts/token.ct");
    unsigned char msg_token[v_msg_token.size()];
    for (int i = 0; i < v_msg_token.size(); ++i) {
        msg_token[i] = v_msg_token[i];
    }
    uint8_t *token_sig = NULL;
    size_t token_sig_length = 0;
    //signature of the token by the server
    EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_server);
    EVP_MD_CTX_init(context_sig);
    if (EVP_DigestSignInit(context_sig, &context_sig_server, NULL, NULL,
                           sig_key_server) != 1) {
        perror("Problem with initialisation of the signature.");
        abort();
    }

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
    EVP_MD_CTX_free(context_sig);

    file_output_results << "Signature by the Server done." << std::endl;

    auto end_time_signature_s = std::chrono::high_resolution_clock::now();
    auto duration_signature_s = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_signature_s - start_time_signature_s);

    file_output_results << "The signature by S has taken " << duration_signature_s.count() << " milliseconds." << std::endl;

    //Server sends to Client the token and its signature

    auto start_time_verif_sig = std::chrono::high_resolution_clock::now();

    //Client receives them, verifies the signature and decrypts the token
    //Verification of the signature, if wrong then quit
    EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_server);
    EVP_MD_CTX_init(context_verif);

    if (EVP_DigestVerifyInit(context_verif, &context_sig_server, NULL, NULL,
                             sig_key_server) != 1) {
        perror("Problem with initialisation of the verification.");
        abort();
    }
    if (EVP_DigestVerify(context_verif, token_sig, token_sig_length, msg_token,
                         sizeof(msg_token)) != 1) {
        perror("Verification of the signature cannot be done.");
        abort();
    }

    //No longer need of the signature items for the client
    EVP_MD_CTX_free(context_verif);
    EVP_PKEY_free(sig_key_server);
    OPENSSL_free(token_sig);

    file_output_results << "Signature verified by the Client." << std::endl;
    auto end_time_verif_sig = std::chrono::high_resolution_clock::now();
    auto duration_verif_sig = std::chrono::duration_cast<std::chrono::microseconds>(end_time_verif_sig - start_time_verif_sig);
    file_output_results << "The verification of the signature by S has taken " << duration_verif_sig.count() << " microseconds." << std::endl;

    seal::Plaintext token_pt;
    std::vector<double> token;
    {
        Stopwatch sw("HE: Decryption and decoding of the token.",
                     file_output_results, 1, Unit::microsecs);
        decryptor.decrypt(b_approx_ct, token_pt);
        encoder.decode(token_pt, token);
    }


    //To compare with the true result
    double euc_dist_true = euclidean_distance(templates[which_template], sample);
    double b = 0.0;
    if (euc_dist_true < bound[0])
        b = 1.0;
    double token_true = b * tau;
    file_output_results << "The token shall be about " << token_true << " and thus, the authentication shall ";
    if (b == 0.0)
        file_output_results << "fail." << std::endl;
    else
        file_output_results << "succeed." << std::endl;



    //Given it is an approximate calculus, we accepted the following error in the computation for the acceptance of the token
    double error_accepted = 0.001;

    if ((token[0] < (tau / 2.0)+error_accepted) && (token[0] > -error_accepted)) {
        file_output_results
                << "The authentication was unsuccessful and the token "
                << token[0]
                << " is not usable to access to the desired service."
                << std::endl;
    } else {
        file_output_results
                << "The authentication was successful and the token "
                << token[0] << " is usable to access to the desired service."
                << std::endl;

    }

    auto end_time_comp = std::chrono::high_resolution_clock::now();
    auto duration_comp = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_comp - start_time_comp);
    file_output_results << std::endl << "The computation phase has taken " << duration_comp.count()/1000.0 << " seconds." << std::endl << std::endl;

    /*
    * END OF THE PROTOCOL
    */
}

void protocol_p_for_accuracy(std::ofstream &file_output_results){
    /*
     *
     * Protocol P execution for accuracy!
     *  202,509 images from "Deep Learning Face Attributes in the Wild
     */

    file_output_results << " A subversion of the protocol P will be executed to verify the accuracy of it." << std::endl;
    file_output_results << " Useless operations for that purpose, e.g. digital signature, are not computed for faster computation." << std::endl << std::endl;

    file_output_results << " Initialisation of the parameters. Done only one time" << std::endl;
    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree,
                                                       {60, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 60}));

    const std::vector<int> bitsizes = {60, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       60};

    //Slot dimension
    const size_t dimension = poly_modulus_degree / 2;
    //scale for encoding
    int power_of_scale = 40;
    double scale = pow(2.0, power_of_scale);
    // Seal context set up, this checks if the parameters make sense
    file_output_results << "\t\t --- Information about computations ---" << std::endl;
    seal::SEALContext context(parms);
    PrintParametersSEAL(context, file_output_results, power_of_scale, 0.0);

    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        std::string filename = "../keys/secret.key";
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
        std::string filename = "../keys/public.key";
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
        std::string filename = "../keys/relin.key";
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
        std::string filename = "../keys/galois.key";
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
    seal::CKKSEncoder encoder(context);

    auto end_time_params = std::chrono::high_resolution_clock::now();
    auto duration_params = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_params - start_time_params);
    file_output_results << "Parameters and keys were set in " << duration_params.count()/1000.0 << " seconds." << std::endl;

    auto start_time_enc_data = std::chrono::high_resolution_clock::now();

    std::string path = "../pict_arrays/";
//    std::string path = "../celeba_encoded/encoding/"; // for the celeba dataset
    std::ifstream reader;
    std::vector<std::vector<double>> templates;
    std::vector<std::string> mapping_index_file_name;
    std::ofstream file_mapping("../mapping_index_file_name.data");
    int cnt_file=0;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of doubles", file_output_results, 1, Unit::microsecs);
        for (const auto &file: std::filesystem::directory_iterator(path)) {
            //the if is only there to avoid to parse the ".gitkeep" file, more robust solutions would be preferable
            if (file.path().string().find(".gitkeep") == std::string::npos) {
                cnt_file+=1;
                mapping_index_file_name.push_back(file.path().string());
                file_mapping << cnt_file << "\t" << file.path().string() << std::endl;
                std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
                FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
                templates.push_back(tmp_vect);
            }
        }
    }
    file_mapping.close();

    // Encryption of the template
    std::vector<seal::Plaintext> templates_pt;
    {
        Stopwatch sw("Encoding of the templates as plaintexts",
                     file_output_results, 1, Unit::secs);
        seal::Plaintext temp_pt;
        for (int i = 0; i < templates.size(); ++i) {
            encoder.encode(templates[i], scale, temp_pt);
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

    auto end_time_enc_data = std::chrono::high_resolution_clock::now();
    auto duration_enc_data = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_enc_data - start_time_enc_data);
    file_output_results << "The database of encoded pictures was encrypted in " << duration_enc_data.count()/1000.0 << " seconds." << std::endl;

    auto start_time_P_execution = std::chrono::high_resolution_clock::now();
    file_output_results << std::endl <<"  ----------- Computation phase --------------" << std::endl;
    int nb_trials = 1000;
    int result_accuracy = 0; // for the accuracy
    file_output_results << "The protocol P will be executed " << nb_trials << " times." <<  std::endl;
    for (int i = 0; i < nb_trials; ++i) {
        //we choose randomly two vectors from the database
        int which_sample = RandomIndexForImage(cnt_file-1);
        int which_template = RandomIndexForImage(cnt_file-1);
        while (which_sample == which_template)
            which_template = RandomIndexForImage(cnt_file-1);

        file_output_results << std::endl << "Execution of P number " << i+1 << " between:" << std::endl;
        file_output_results << "Vector: " << which_sample+1 << " starting by " << templates[which_sample][0] << std::endl;
        file_output_results << "Vector: " << which_template+1 << " starting by " << templates[which_template][0] << std::endl;


        seal::Ciphertext euc_dist_ct;
        enc_euclidean_dist(templates_ct[which_sample], templates_ct[which_template], euc_dist_ct, encoder,
                               evaluator, gal_keys, relin_keys, scale);

        std::vector<double> bound(dimension, 0.3);
        //face_recognition library python has a 0.6 bound for the euclidean distance
        //here we have the square of the distance, and 0.6^2 = 0.36
        //we decided to be a bit more strict and compare with 0.3
        seal::Plaintext bound_pt;
        seal::Ciphertext bound_ct;
        encoder.encode(bound, scale, bound_pt);
        encryptor.encrypt(bound_pt, bound_ct);
        evaluator.mod_switch_to_inplace(bound_ct, euc_dist_ct.parms_id());
        euc_dist_ct.scale() = scale;
        evaluator.sub_inplace(bound_ct, euc_dist_ct);

        seal::Ciphertext b_approx_ct, tmp_approx_ct;
        enc_g3(bound_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
        enc_f4(b_approx_ct, tmp_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
        enc_f3(tmp_approx_ct, b_approx_ct, encoder, decryptor, evaluator, relin_keys, scale);
        enc_final_approx_inplace(b_approx_ct, encoder, decryptor, evaluator, scale);

        double tau = abs(RandomDouble());

        // Server creates the plaintext for Tau
        seal::Plaintext tau_pt;
        encoder.encode(tau, scale, tau_pt);
        evaluator.mod_switch_to_inplace(tau_pt, b_approx_ct.parms_id());
        evaluator.multiply_plain_inplace(b_approx_ct, tau_pt);

        seal::Plaintext token_pt;
        std::vector<double> token;
        decryptor.decrypt(b_approx_ct, token_pt);
        encoder.decode(token_pt, token);


        //Protocol P executed as if it would be on cleartexts
        bool true_P = false;
        double euc_dist_true = euclidean_distance(templates[which_sample], templates[which_template]);
        if (euc_dist_true < bound[0])
            true_P = true;
        file_output_results << "The square euclidean distance is equal to " << euc_dist_true << std::endl;
        file_output_results << "The authentication shall ";
        if (true_P)
            file_output_results << "succeed." << std::endl;
        else
            file_output_results << "fail." << std::endl;

        bool he_P = false;
        //Given it is an approximate calculus, we accepted the following error in the computation for the acceptance of the token
        double error_accepted = 0.001;

        if ((token[0] < (tau / 2.0) + error_accepted) && (token[0] > -error_accepted)) {
            file_output_results
                    << "The authentication was unsuccessful and the token "
                    << token[0]
                    << " is not usable to access to the desired service."
                    << std::endl;
        } else {
            he_P = true;
            file_output_results
                    << "The authentication was successful and the token "
                    << token[0] << " is usable to access to the desired service."
                    << std::endl;

        }

        if (true_P == he_P)
            result_accuracy += 1;
    }
    file_output_results << std::endl << "Over " << nb_trials << " executions of P, " << result_accuracy << " were successful." << std::endl;
    file_output_results << "The accuracy is thus of " << ((1.0*result_accuracy)/nb_trials)*100.0 << "%." <<  std::endl;
    auto end_time_P_execution = std::chrono::high_resolution_clock::now();
    auto duration_P_execution = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_P_execution - start_time_P_execution);
    file_output_results << "All the executions of P were executed in " << duration_P_execution.count()/1000.0 << " seconds." << std::endl;
}


void test_approx_function(){
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree,
                                                       {60, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 40, 40, 40, 40,
                                                        40, 40, 60}));
    // use parameters below to have more multiplicative depth but less precision due to the scale being less
//    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, {60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,30,30,30,30,30,30,30,30,30,30,30,30, 60}));
    const std::vector<int> bitsizes = {60, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                                       60};
//    const std::vector<int> bitsizes = {60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,30,30,30,30,30,30,30,30,30,30,30,30, 60};
    //Slot dimension
    const size_t dimension = poly_modulus_degree / 2;
    //scale for encoding
    int power_of_scale = 40; // put 30 if the other parameters are chosen
    double scale = pow(2.0, power_of_scale);
    seal::SEALContext context(parms);
    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;

    std::string filename = "../keys/secret.key";
    if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
    {
        std::ifstream fs(filename, std::ios::binary);
        secret_key.load(context, fs);
    }
    else {
        std::ofstream fs(filename, std::ios::binary);
        secret_key = keygen.secret_key();
        secret_key.save(fs);
    }

    seal::PublicKey public_key;

    filename = "../keys/public.key";
    if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
    {
        std::ifstream fs(filename, std::ios::binary);
        public_key.load(context, fs);
    }
    else {
        keygen.create_public_key(public_key);
        std::ofstream fs(filename, std::ios::binary);
        public_key.save(fs);
    }

    seal::RelinKeys relin_keys;
    filename = "../keys/relin.key";
    if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename))
    {
        std::ifstream fs(filename, std::ios::binary);
        relin_keys.load(context, fs);
    }
    else {
        keygen.create_relin_keys(relin_keys);
        std::ofstream fs(filename, std::ios::binary);
        relin_keys.save(fs);
    }


    seal::GaloisKeys gal_keys;
    filename = "../keys/galois.key";
    if (std::filesystem::exists(filename) && !std::filesystem::is_empty(filename)){
        std::ifstream fs(filename, std::ios::binary);
        gal_keys.load(context, fs);
    }
    else {
        keygen.create_galois_keys(gal_keys);
        std::ofstream fs(filename, std::ios::binary);
        gal_keys.save(fs);
    }

    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::CKKSEncoder encoder(context);

    double a = 0.145345632;
    double b = 0.4;

    double approx = a - b;
    std::cout << "a - b is equal to " << approx << std::endl;
    double tmp_res;
    int loop_g = 1;
    int loop_f = 2;
    for (int i = 0; i < loop_g; ++i) {
        tmp_res = g4(approx);
        approx = tmp_res;
        std::cout << "The approximate value is equal to " << approx << " after "
        << i+1 << " the application of g4." << std::endl;
    }
    for (int i = 0; i < loop_f; ++i) {
        tmp_res = f4(approx);
        approx = tmp_res;
        std::cout << "The approximate value is equal to " << approx << " after "
                  << i+1 << " the application of f4." << std::endl;
    }
    final_approx_inplace(approx);
    std::cout << "The final approximate value we are looking for is "
    << approx << std::endl;

    seal::Plaintext approx_pt;
    seal::Ciphertext approx_ct, approx_result_ct;
    encoder.encode(a - b, scale, approx_pt);
    encryptor.encrypt(approx_pt, approx_ct);
    {
        std::ofstream fs("../ciphertexts/approx_result.ct", std::ios::binary);
        approx_ct.save(fs);
    }
    seal::Plaintext tmp_pt;
    std::vector<double> tmp_dec;
    decryptor.decrypt(approx_ct, tmp_pt);
    encoder.decode(tmp_pt, tmp_dec);
    PrintVectorUntilN(tmp_dec, 10);

    for (int i = 0; i < 3; ++i) {
        std::cout << approx_result_ct.coeff_modulus_size() << " of multiplicative depth is left." << std::endl;
        std::ifstream is;
        is.open("../ciphertexts/approx_result.ct", std::ios::binary);
        seal::Ciphertext tmp_approx;
        tmp_approx.load(context, is);
        is.close();
        enc_g4(tmp_approx, approx_result_ct, encoder, decryptor, evaluator,
                relin_keys, scale);
        std::ofstream fs("../ciphertexts/approx_result.ct", std::ios::binary);
        approx_result_ct.save(fs);
    }
    enc_final_approx_inplace(approx_result_ct, encoder, decryptor, evaluator,
                         scale);

    seal::Plaintext approx_result_pt;
    std::vector<double> approx_result;
    decryptor.decrypt(approx_result_ct, approx_result_pt);
    encoder.decode(approx_result_pt, approx_result);
    PrintVectorUntilN(approx_result, 10);
}