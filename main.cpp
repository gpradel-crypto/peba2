//
// Created by gpr on 16/03/2022.
//
#include <iostream>
#include <seal/seal.h>
#include <fstream>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "src/math.h"
#include "src/utilities.h"

int main () {

    //Time of the full suite of tests
    auto start_time_full = std::chrono::high_resolution_clock::now();

    std::ofstream file_output_results("../results.data");

    /*
     *  Precomputation phase
     */
    file_output_results << "  ----------- Precomputation phase --------------" << std::endl;

    // Client side

    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 8192; // power of 2 available: 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {39, 30, 40}));
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, {49, 40, 40, 40, 49}));
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50})); // for big modulus


    //Number of rescaling allowed (amount of multiplication that are possible)
//    const vector<int> bitsizes = {39, 30, 40};
//    const vector<int> bitsizes = {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50};
    const std::vector<int> bitsizes = {49, 40, 40, 40, 49};
    u_int nb_rescaling = bitsizes.size() - 2;
    //Slot dimension
    const size_t dimension = poly_modulus_degree/2;
    //scale for encoding
    int power_of_scale = 40;
    double scale = pow(2.0, power_of_scale);


    // Seal context set up, this checks if the parameters make sense
    file_output_results << "\t\t --- Information about computations ---" << std::endl;
    seal::SEALContext context(parms);
    PrintParametersSEAL(context, file_output_results);
    file_output_results << "|    Scale: 2^" << power_of_scale << std::endl;
    file_output_results << "|    Number of rescaling allowed: " << nb_rescaling << std::endl;
    file_output_results << "\\" << std::endl << std::endl;
    file_output_results << "Dimension of the vector of inputs: " << dimension << std::endl;
//    cout << "The vectors of inputs are filled with doubles between " << LOWER_BOUND << " and " << UPPER_BOUND << endl;
//    cout << "The vectors of inputs are filled with doubles between " << exp(LOWER_BOUND) << " and " << exp(UPPER_BOUND) << endl;
//    cout << "The vectors of inputs are filled with doubles between " << -exp(LOWER_BOUND) << " and " << -exp(UPPER_BOUND) << endl;


    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        Stopwatch sw("Generation of the secret key", file_output_results, 1);
        secret_key = keygen.secret_key();
        std::ofstream fs("../keys/secret.key", std::ios::binary);
        secret_key.save(fs);
    }

    seal::PublicKey public_key;
    {
        Stopwatch sw("Generation of the public key", file_output_results, 1);
        keygen.create_public_key(public_key);
        std::ofstream fs("../keys/public.key", std::ios::binary);
        public_key.save(fs);
    }

    seal::RelinKeys relin_keys;
    {
        Stopwatch sw("Generation of the relinearisation key", file_output_results, 1);
        keygen.create_relin_keys(relin_keys);
        std::ofstream fs("../keys/relin.key", std::ios::binary);
        relin_keys.save(fs);
    }

    seal::GaloisKeys gal_keys;
    {
        Stopwatch sw("Generation of the galois key", file_output_results, 1);
        keygen.create_galois_keys(gal_keys);
        std::ofstream fs("../keys/galois.key", std::ios::binary);
        gal_keys.save(fs);
    }

    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::CKKSEncoder encoder(context);
//    size_t slot_count = encoder.slot_count();
//    cout << "Number of slots: " << slot_count << endl;


//    // Create of the signature key of the client
//    EVP_PKEY *sig_key_client = NULL;
//    EVP_PKEY_CTX *context_sig_client = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
//    EVP_PKEY_keygen_init(context_sig_client);
//    EVP_PKEY_keygen(context_sig_client, &sig_key_client);
//    {
//        Stopwatch sw("Generation of the public key for signature of the client", file_output_results, 1);
//        FILE *file;
//        file = fopen("../keys/signature_client_pub.key", "wb");
//        if (file == NULL)
//        {
//            perror("Error opening file to save public signature key.");
//            return EXIT_FAILURE;
//        }
//        PEM_write_PUBKEY(file, sig_key_client);
//        fclose(file);
//    }
//    {
//        Stopwatch sw("Generation of the private key for signature of the client", file_output_results, 1);
//        FILE *file;
//        file = fopen("../keys/signature_client_priv.key", "wb");
//        if (file == NULL)
//        {
//            perror("Error opening file to save private signature key.");
//            return EXIT_FAILURE;
//        }
//        PEM_write_PrivateKey(file, sig_key_client, NULL, NULL, 0, NULL, NULL);
//        fclose(file);
//    }

    //Generation of the templates database on the side of the server
//    std::vector<double> temp = create_vector_input(dimension);
//    print_vector(temp);

    std::string path = "../pict_arrays/";
    std::ifstream reader;
    std::vector<std::vector<double>> templates;
    for (const auto & file : std::filesystem::directory_iterator(path)) {
        std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
        FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
        templates.push_back(tmp_vect);
    }

    // Encryption of the template
    std::vector<seal::Plaintext> templates_pt;
    {
        Stopwatch sw("Encoding of the templates as plaintexts", file_output_results, 1);
        seal::Plaintext temp_pt;
        for (int i = 0; i < templates.size(); ++i) {
            encoder.encode(templates[i], scale,temp_pt);
            templates_pt.push_back(temp_pt);
        }
    }
    std::vector<seal::Ciphertext> templates_ct;
    {
        Stopwatch sw("Encryption of the templates", file_output_results, templates_pt.size());
        seal::Ciphertext temp_ct;
        for (int i = 0; i < templates_pt.size(); ++i) {
            encryptor.encrypt(templates_pt[i], temp_ct);
            templates_ct.push_back(temp_ct);
        }
    }
    //Save the ciphertext in a file
    {
        Stopwatch sw("Serialisation of the encrypted templates", file_output_results, templates_pt.size());
        for (int i = 0; i < templates_ct.size(); ++i) {
            std::string file_name_ct = "../ciphertexts/template";
            file_name_ct.append(std::to_string(i + 1));
            file_name_ct.append(".ct");
            std::ofstream fs(file_name_ct, std::ios::binary);
            templates_ct[i].save(fs);
        }
    }

    // Server side
    // Create of the signature key of the server
    EVP_PKEY *sig_key_server = NULL;
    EVP_PKEY_CTX *context_sig_server = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(context_sig_server);
    EVP_PKEY_keygen(context_sig_server, &sig_key_server);
    {
        Stopwatch sw("Generation of the public key for signature of the server", file_output_results, 1);
        FILE *file;
        file = fopen("../keys/signature_server_pub.key", "wb");
        if (file == NULL)
        {
            perror("Error opening file to save public signature key.");
            return EXIT_FAILURE;
        }
        PEM_write_PUBKEY(file, sig_key_server);
        fclose(file);
    }
    {
        Stopwatch sw("Generation of the private key for signature of the server", file_output_results, 1);
        FILE *file;
        file = fopen("../keys/signature_server_priv.key", "wb");
        if (file == NULL)
        {
            perror("Error opening file to save private signature key.");
            return EXIT_FAILURE;
        }
        PEM_write_PrivateKey(file, sig_key_server, NULL, NULL, 0, NULL, NULL);
        fclose(file);
    }


    //Client sends the template encrypted to the server


    //Server side

    /*
     * Computation phase
     *
     */

    //Client side

    //Generation of the sample
    std::string path_sample = "../pict_arrays/encoding_INCERT_U Photo GPR.jpg.data";
    std::vector<double> sample = ParseEncoding(reader, path_sample);
    FillVectorUntilN(sample, encoder.slot_count(), 0.0);

    // Encryption of the template
    seal::Plaintext sample_pt;
    {
        Stopwatch sw("Encoding of the sample as a plaintext", file_output_results, 1);
        encoder.encode(sample, scale,sample_pt);
    }
    seal::Ciphertext sample_ct;
    {
        Stopwatch sw("Encryption of the sample", file_output_results, 1);
        encryptor.encrypt(sample_pt, sample_ct);
    }
    //Save the ciphertext in a file
    {
        std::ofstream fs("../ciphertexts/sample.ct", std::ios::binary);
        sample_ct.save(fs);
    }
    //Write the ciphertext as a char* for signature.
//    std::vector<char> v_msg_sample_ct = FromFileToVect("../ciphertexts/sample.ct");
//    unsigned char msg_sample_ct[v_msg_sample_ct.size()];
//    for (int i = 0; i < v_msg_sample_ct.size(); ++i) {
//        msg_sample_ct[i] = v_msg_sample_ct[i];
//    }
//    uint8_t* sample_ct_sig = NULL;
//    size_t sample_ct_sig_length = 0;
//    //signature of the ciphertext by the client
//    EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
////    EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_client);
//    EVP_MD_CTX_init(context_sig);
////    if (EVP_DigestSignInit(context_sig, &context_sig_client, NULL, NULL, sig_key_client) !=1 ){
////        perror("Problem with initialisation of the signature.");
////        return EXIT_FAILURE;
////    }
//    if (EVP_DigestSign(context_sig, sample_ct_sig, &sample_ct_sig_length , msg_sample_ct, sizeof(msg_sample_ct)) != 1)
//    {
//        perror("Signature cannot be done.");
//        return EXIT_FAILURE;
//    }
//    sample_ct_sig = (uint8_t*) malloc(sample_ct_sig_length * sizeof(uint8_t));
//    if (EVP_DigestSign(context_sig, sample_ct_sig, &sample_ct_sig_length , msg_sample_ct, sizeof(msg_sample_ct)) != 1)
//    {
//        perror("Signature cannot be done.");
//        return EXIT_FAILURE;
//    }
//    EVP_MD_CTX_free(context_sig);


    //Client sends the sample encrypted to the server
    // Server side

//    //Verification of the signature, if wrong then quit
//    EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
////    EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_client);
//    EVP_MD_CTX_init(context_verif);
//
////    if (EVP_DigestVerifyInit(context_verif, &context_sig_client, NULL, NULL, sig_key_client) !=1 ){
////        perror("Problem with initialisation of the verification.");
////        return EXIT_FAILURE;
////    }
//    if (EVP_DigestVerify(context_verif, sample_ct_sig, sample_ct_sig_length, msg_sample_ct, sizeof(msg_sample_ct)) != 1){
//        perror("Verification of the signature cannot be done.");
//        return EXIT_FAILURE;
//    }
//
//    //No longer need of the signature items for the client
//    EVP_MD_CTX_free(context_verif);
////    EVP_PKEY_free(sig_key_client);
//    OPENSSL_free(sample_ct_sig);

    seal::Ciphertext euc_dist_ct;
    {
        Stopwatch sw("HE: Computation of the euclidean distance (first part of the function f) between the template and the sample", file_output_results, 1);
        enc_euclidean_dist(templates_ct[15], sample_ct, euc_dist_ct, encoder, evaluator, gal_keys, relin_keys, scale);
    }

    seal::Plaintext enc_euclidean_dist_pt;
    std::vector<double> euclidean_dist_dec;
    {
        Stopwatch sw("HE: Decryption of the euclidean distance (first part of the function f) between the template and the sample", file_output_results, 1);
        decryptor.decrypt(euc_dist_ct, enc_euclidean_dist_pt);
    }
    {
        Stopwatch sw("HE: Decoding of the euclidean distance (first part of the function f) between the template and the sample", file_output_results, 1);
        encoder.decode(enc_euclidean_dist_pt, euclidean_dist_dec);
    }

//    PrintVector(euclidean_dist_dec);

//    verification of the result
    file_output_results << "Verification if the ciphertext euclidean distance calculation is accurate." << std::endl;
    double euc_dist_true = euclidean_distance(templates[15], sample);
    file_output_results << "The true result is " << euc_dist_true << " and the decrypted result is " << euclidean_dist_dec[0] << std::endl;

    std::vector<double> bound = {0.4}; // this choice is based on the python library face_recognition
    seal::Plaintext bound_pt;
    encoder.encode(bound, scale, bound_pt);
    {
        Stopwatch sw("HE: Computation of the end of the function f", file_output_results,1);
        evaluator.rescale_to_next_inplace(euc_dist_ct);
        evaluator.mod_switch_to_next_inplace(bound_pt);
        euc_dist_ct.scale() = scale;
        evaluator.sub_plain_inplace(euc_dist_ct, bound_pt);
    }

    // Server generates the random number Tau
    double tau = abs(RandomDouble());

    // Needs to save tau as a file to sign it after. And normally also 0.0, but not done here
    // but it's not working without the comparison done one the euc dist with the bound

    // Server creates the plaintext for Tau
    seal::Plaintext tau_pt;
    {
        Stopwatch sw("Generation of tau, encoding and modulus switch for computation.", file_output_results,1);
        encoder.encode(tau, scale, tau_pt);
    // Server applies g function
        evaluator.mod_switch_to_next_inplace(tau_pt);
    }
    {
        Stopwatch sw("HE: Computation of the function g", file_output_results,1);
        evaluator.multiply_plain_inplace(euc_dist_ct, tau_pt);
    }
    file_output_results << "Calculation of the token y completed." << std::endl;
    // Save the token y encrypted in a file to send it to client
    {
        std::ofstream fs("../ciphertexts/token.ct", std::ios::binary);
        euc_dist_ct.save(fs);
    }
    //Write tau as a char* for signature.
    std::vector<char> v_msg_token = FromFileToVect("../ciphertexts/token.ct");
    unsigned char msg_token[v_msg_token.size()];
    for (int i = 0; i < v_msg_token.size(); ++i) {
        msg_token[i] = v_msg_token[i];
    }
    uint8_t* token_sig = NULL;
    size_t token_sig_length = 0;
    //signature of the token by the server
    EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_server);
    EVP_MD_CTX_init(context_sig);
    if (EVP_DigestSignInit(context_sig, &context_sig_server, NULL, NULL, sig_key_server) !=1 ){
        perror("Problem with initialisation of the signature.");
        return EXIT_FAILURE;
    }

    if (EVP_DigestSign(context_sig, token_sig, &token_sig_length , msg_token, sizeof(msg_token)) != 1)
    {
        perror("Signature cannot be done.");
        return EXIT_FAILURE;
    }
    token_sig = (uint8_t*) malloc(token_sig_length * sizeof(uint8_t));
    if (EVP_DigestSign(context_sig, token_sig, &token_sig_length , msg_token, sizeof(msg_token)) != 1)
    {
        perror("Signature cannot be done.");
        return EXIT_FAILURE;
    }
    EVP_MD_CTX_free(context_sig);

    file_output_results << "Signature by the Server done." << std::endl;


    //Server sends to Client the token and its signature

    //Client receives them, verifies the signature and decrypts the token
    //Verification of the signature, if wrong then quit
    EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_server);
    EVP_MD_CTX_init(context_verif);

    if (EVP_DigestVerifyInit(context_verif, &context_sig_server, NULL, NULL, sig_key_server) !=1 ){
        perror("Problem with initialisation of the verification.");
        return EXIT_FAILURE;
    }
    if (EVP_DigestVerify(context_verif, token_sig, token_sig_length, msg_token, sizeof(msg_token)) != 1){
        perror("Verification of the signature cannot be done.");
        return EXIT_FAILURE;
    }

    //No longer need of the signature items for the client
    EVP_MD_CTX_free(context_verif);
    EVP_PKEY_free(sig_key_server);
    OPENSSL_free(token_sig);

    file_output_results << "Signature verified by the Client." << std::endl;

    seal::Plaintext token_pt;
    std::vector<double> token;
    {
        Stopwatch sw("HE: Decryption and decoding of the token.", file_output_results,1);
        decryptor.decrypt(euc_dist_ct, token_pt);
        encoder.decode(token_pt, token);
    }

    if (token[0] < 0){
        file_output_results << "The authentication was successful and the token " << token[0] << " is usable to access to the desired service." << std::endl;
    }
    else {
        file_output_results << "The authentication was unsuccessful and the token " << token[0] << " is not usable to access to the desired service." << std::endl;
    }


    auto end_time_full = std::chrono::high_resolution_clock::now();
    auto duration_full = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_full - start_time_full);
    file_output_results << std::endl << std::endl << std::endl << "The full protocol has taken " << duration_full.count() << " milliseconds." << std::endl;

    /*
     * END OF THE PROTOCOL
     */
    file_output_results.close();
    std::ifstream file_output_results_display;
    file_output_results_display.open("../results.data");
    PrintFile(file_output_results_display);

    return 0;
}