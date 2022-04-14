//
// Created by gpr on 16/03/2022.
//
#include <iostream>
#include <seal/seal.h>
#include <fstream>
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

    //Creation of the keys
    // Seal encryption set up
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 4096; // power of 2 available: 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {39, 30, 40}));
    //parms.set_poly_modulus_degree(poly_modulus_degree);
    //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {49, 40, 40, 40, 49}));
    //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50})); // for big modulus


    //Number of rescaling allowed (amount of multiplication that are possible)
    const vector<int> bitsizes = {39, 30, 40};
//    const vector<int> bitsizes = {50, 50, 40, 40, 40 , 40, 40, 40, 40, 50};
//    const vector<int> bitsizes = {49, 40, 40, 40, 49};
    u_int nb_rescaling = bitsizes.size() - 2;
    //Slot dimension
    const size_t dimension = poly_modulus_degree/2;
    //scale for encoding
    int power_of_scale = 30;
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

    // Create a vector of plaintexts
    CKKSEncoder encoder(context);
//    size_t slot_count = encoder.slot_count();
//    cout << "Number of slots: " << slot_count << endl;

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

    //Client sends the sample encrypted to the server
    // Server side

    Ciphertext euc_dist_ct;
    {
        Stopwatch sw("Computation of the euclidean distance between the template and the sample");
        enc_euclidean_dist(temp_ct, sample_ct, euc_dist_ct, encoder, evaluator, gal_keys, relin_keys, scale);
    }

    // Server generates the random number Tau
    double tau = random_double();
    // Server creates the plaintext for Tau
    Plaintext tau_pt;
    encoder.encode(tau, scale, tau_pt);
    // Server applies g function
    cout << "Encoding of tau done" << endl;

    //cout << "encrypted_ntt is " << euc_dist_ct.parms_id() << endl;
    //cout << "plain_ntt is " << tau_pt.parms_id() << endl;
    evaluator.multiply_plain_inplace(euc_dist_ct, tau_pt);
    cout << "calculation of the token y done" << endl;
    // Save the token y encrypted in a file to send it to client
    {
        ofstream fs("token.ct", ios::binary);
        euc_dist_ct.save(fs);
    }
    //Server sends to Client the token

    //Client receives it and decrypts it
    Plaintext token_pt;
    decryptor.decrypt(euc_dist_ct, token_pt);
    cout << "decryption of the token done" << endl;
    vector<double> token;
    encoder.decode(token_pt, token);

    /*
     * END OF THE PROTOCOL
     */

    //verification of the result
    cout << "Verification if the ciphertext calculation is accurate." << endl;
    double euc_dist_true = euclidean_distance(temp, sample);

    cout << "The true result is " << euc_dist_true << " and the decrypted result is " << token[0] << endl;
    return 0;
}