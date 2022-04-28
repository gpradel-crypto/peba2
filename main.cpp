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

using namespace std;
using namespace seal;


int main () {

    /*
     *  Precomputation phase
     */
    cout << "  ----------- Precomputation phase --------------" << endl;

    // Client side

    //Creation of the homomorphic keys
    // Seal encryption set up
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192; // power of 2 available: 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {39, 30, 40}));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {49, 40, 40, 40, 49}));
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50})); // for big modulus


    //Number of rescaling allowed (amount of multiplication that are possible)
//    const vector<int> bitsizes = {39, 30, 40};
//    const vector<int> bitsizes = {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50};
    const vector<int> bitsizes = {49, 40, 40, 40, 49};
    u_int nb_rescaling = bitsizes.size() - 2;
    //Slot dimension
    const size_t dimension = poly_modulus_degree/2;
    //scale for encoding
    int power_of_scale = 40;
    double scale = pow(2.0, power_of_scale);


    // Seal context set up, this checks if the parameters make sense
    cout << "\t\t --- Information about computations ---" << endl;
    SEALContext context(parms);
    print_parameters(context);
    cout << "|    Scale: 2^" << power_of_scale << endl;
    cout << "|    Number of rescaling allowed: " << nb_rescaling << endl;
    cout << "\\" << std::endl << std::endl;
    cout << "Dimension of the vector of inputs: " << dimension << endl;
//    cout << "The vectors of inputs are filled with doubles between " << LOWER_BOUND << " and " << UPPER_BOUND << endl;
//    cout << "The vectors of inputs are filled with doubles between " << exp(LOWER_BOUND) << " and " << exp(UPPER_BOUND) << endl;
//    cout << "The vectors of inputs are filled with doubles between " << -exp(LOWER_BOUND) << " and " << -exp(UPPER_BOUND) << endl;


    //Set up the keys
    KeyGenerator keygen(context);
    SecretKey secret_key;
    {
        Stopwatch sw("Generation of the secret key");
        secret_key = keygen.secret_key();
        ofstream fs("secret.key", ios::binary);
        secret_key.save(fs);
    }

    PublicKey public_key;
    {
        Stopwatch sw("Generation of the public key");
        keygen.create_public_key(public_key);
        ofstream fs("public.key", ios::binary);
        public_key.save(fs);
    }

    RelinKeys relin_keys;
    {
        Stopwatch sw("Generation of the relinearisation key");
        keygen.create_relin_keys(relin_keys);
        ofstream fs("relin.key", ios::binary);
        relin_keys.save(fs);
    }

    GaloisKeys gal_keys;
    {
        Stopwatch sw("Generation of the galois key");
        keygen.create_galois_keys(gal_keys);
        ofstream fs("galois.key", ios::binary);
        gal_keys.save(fs);
    }

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
//    size_t slot_count = encoder.slot_count();
//    cout << "Number of slots: " << slot_count << endl;


    // Create of the signature key of the client
    EVP_PKEY *sig_key_client = NULL;
    EVP_PKEY_CTX *context_sig_client = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(context_sig_client);
    EVP_PKEY_keygen(context_sig_client, &sig_key_client);
    {
        Stopwatch sw("Generation of the public key for signature of the client");
        FILE *file;
        file = fopen("../signature_client_pub.key", "wb");
        if (file == NULL)
        {
            perror("Error opening file to save public signature key.");
            return EXIT_FAILURE;
        }
        PEM_write_PUBKEY(file, sig_key_client);
        fclose(file);
    }
    {
        Stopwatch sw("Generation of the private key for signature of the client");
        FILE *file;
        file = fopen("../signature_client_priv.key", "wb");
        if (file == NULL)
        {
            perror("Error opening file to save private signature key.");
            return EXIT_FAILURE;
        }
        PEM_write_PrivateKey(file, sig_key_client, NULL, NULL, 0, NULL, NULL);
        fclose(file);
    }

    //Generation of the template
    vector<double> temp = create_vector_input(dimension);
    print_vector(temp);

    // Encryption of the template
    Plaintext temp_pt;
    {
        Stopwatch sw("Encoding of the template as a plaintext");
        encoder.encode(temp, scale,temp_pt);
    }
    Ciphertext temp_ct;
    {
        Stopwatch sw("Encryption of the template");
        encryptor.encrypt(temp_pt, temp_ct);
    }
    //Save the ciphertext in a file
    {
        ofstream fs("temp.ct", ios::binary);
        temp_ct.save(fs);
    }

    // Server side
    // Create of the signature key of the server
    EVP_PKEY *sig_key_server = NULL;
    EVP_PKEY_CTX *context_sig_server = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(context_sig_server);
    EVP_PKEY_keygen(context_sig_server, &sig_key_server);
    {
        Stopwatch sw("Generation of the public key for signature of the server");
        FILE *file;
        file = fopen("../signature_server_pub.key", "wb");
        if (file == NULL)
        {
            perror("Error opening file to save public signature key.");
            return EXIT_FAILURE;
        }
        PEM_write_PUBKEY(file, sig_key_server);
        fclose(file);
    }
    {
        Stopwatch sw("Generation of the private key for signature of the server");
        FILE *file;
        file = fopen("../signature_server_priv.key", "wb");
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
    vector<double> sample = create_vector_input(dimension);
    print_vector(sample);

    // Encryption of the template
    Plaintext sample_pt;
    {
        Stopwatch sw("Encoding of the sample as a plaintext");
        encoder.encode(sample, scale,sample_pt);
    }
    Ciphertext sample_ct;
    {
        Stopwatch sw("Encryption of the sample");
        encryptor.encrypt(sample_pt, sample_ct);
    }
    //Save the ciphertext in a file
    {
        ofstream fs("sample.ct", ios::binary);
        temp_ct.save(fs);
    }
    //Write the ciphertext as a char* for signature.
    vector<char> v_msg_sample_ct = FromFileToVect("sample.ct");
    unsigned char msg_sample_ct[v_msg_sample_ct.size()];
    for (int i = 0; i < v_msg_sample_ct.size(); ++i) {
        msg_sample_ct[i] = v_msg_sample_ct[i];
    }
    uint8_t* sample_ct_sig = NULL;
    size_t sample_ct_sig_length = 0;
    //signature of the ciphertext by the client
    EVP_MD_CTX *context_sig = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_sig, context_sig_client);
    EVP_MD_CTX_init(context_sig);
    if (EVP_DigestSignInit(context_sig, &context_sig_client, NULL, NULL, sig_key_client) !=1 ){
        perror("Problem with initialisation of the signature.");
        return EXIT_FAILURE;
    }

    if (EVP_DigestSign(context_sig, sample_ct_sig, &sample_ct_sig_length , msg_sample_ct, sizeof(msg_sample_ct)) != 1)
    {
        perror("Signature cannot be done.");
        return EXIT_FAILURE;
    }
    sample_ct_sig = (uint8_t*) malloc(sample_ct_sig_length * sizeof(uint8_t));
    if (EVP_DigestSign(context_sig, sample_ct_sig, &sample_ct_sig_length , msg_sample_ct, sizeof(msg_sample_ct)) != 1)
    {
        perror("Signature cannot be done.");
        return EXIT_FAILURE;
    }
    EVP_MD_CTX_free(context_sig);


    //Client sends the sample encrypted to the server along with its signature
    // Server side

    //Verification of the signature, if wrong then quit
    EVP_MD_CTX *context_verif = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(context_verif, context_sig_client);
    EVP_MD_CTX_init(context_verif);

    if (EVP_DigestVerifyInit(context_verif, &context_sig_client, NULL, NULL, sig_key_client) !=1 ){
        perror("Problem with initialisation of the verification.");
        return EXIT_FAILURE;
    }
    if (EVP_DigestVerify(context_verif, sample_ct_sig, sample_ct_sig_length, msg_sample_ct, sizeof(msg_sample_ct)) != 1){
        perror("Verification of the signature cannot be done.");
        return EXIT_FAILURE;
    }

    //No longer need of the signature items for the client
    EVP_MD_CTX_free(context_verif);
    EVP_PKEY_free(sig_key_client);
    OPENSSL_free(sample_ct_sig);

    Ciphertext euc_dist_ct;
    {
        Stopwatch sw("Computation of the euclidean distance between the template and the sample");
        enc_euclidean_dist(temp_ct, sample_ct, euc_dist_ct, encoder, evaluator, gal_keys, relin_keys, scale);
    }

    Plaintext enc_euclidean_dist_pt;
    decryptor.decrypt(euc_dist_ct, enc_euclidean_dist_pt);
    cout << "decryption of the euc dist done" << endl;
    vector<double> euclidean_dist_dec;
    encoder.decode(enc_euclidean_dist_pt, euclidean_dist_dec);
    print_vector(euclidean_dist_dec);

    //verification of the result
    cout << "Verification if the ciphertext euclidean distance calculation is accurate." << endl;
    double euc_dist_true = euclidean_distance(temp, sample);

    cout << "The true result is " << euc_dist_true << " and the decrypted result is " << euclidean_dist_dec[0] << endl;

    vector<double> bound = {1000.0};
    Plaintext bound_pt;
    encoder.encode(bound, scale, bound_pt);
    evaluator.rescale_to_next_inplace(euc_dist_ct);
    evaluator.mod_switch_to_next_inplace(bound_pt);
    euc_dist_ct.scale() = scale;
    evaluator.sub_plain_inplace(euc_dist_ct, bound_pt);

    // Server generates the random number Tau
    double tau = abs(random_double());
    cout << "Tau is equal to " << tau << endl;
    // Server creates the plaintext for Tau
    Plaintext tau_pt;
    encoder.encode(tau, scale, tau_pt);
    // Server applies g function
    cout << "Encoding of tau done" << endl;
    evaluator.mod_switch_to_next_inplace(tau_pt);
    evaluator.multiply_plain_inplace(euc_dist_ct, tau_pt);
    cout << "calculation of the token y done" << endl;
    // Save the token y encrypted in a file to send it to client
    {
        ofstream fs("token.ct", ios::binary);
        euc_dist_ct.save(fs);
    }
    //Write the ciphertext as a char* for signature.
    vector<char> v_msg_token = FromFileToVect("token.ct");
    unsigned char msg_token[v_msg_token.size()];
    for (int i = 0; i < v_msg_token.size(); ++i) {
        msg_token[i] = v_msg_token[i];
    }
    uint8_t* token_sig = NULL;
    size_t token_sig_length = 0;
    //signature of the token by the client
    context_sig = EVP_MD_CTX_new();
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


    //Server sends to Client the token and its signature

    //Client receives them, verifies the signature and decrypts the token
    //Verification of the signature, if wrong then quit
    context_verif = EVP_MD_CTX_new();
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

    Plaintext token_pt;
    decryptor.decrypt(euc_dist_ct, token_pt);
    cout << "decryption of the token done" << endl;
    vector<double> token;
    encoder.decode(token_pt, token);
    cout << "The true token is " << (euc_dist_true - bound[0]) * tau << " and the decrypted token is " << token[0] << endl;
    print_vector(token);


    /*
     * END OF THE PROTOCOL
     */

    return 0;
}