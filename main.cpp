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

const int DIMENSION = 16;

int main () {

    /*
     *  Precomputation phase
     */

    // Client side

    //Creation of the keys
    // Seal encryption set up
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {39, 30, 40}));

    //scale for encoding
    double scale = pow(2.0, 30);

    // Seal context set up, this checks if the parameters make sense
    SEALContext context(parms);
    print_parameters(context);
    cout << "Maximal allowed coeff_modulus bit-count for this poly_modulus_degree " << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;

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
    vector<double> temp = create_vector_input(DIMENSION);
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
    vector<double> sample = create_vector_input(DIMENSION);
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

    Ciphertext euc_dist;
    {
        Stopwatch sw("Computation of the euclidean distance between the template and the sample");
        enc_euclidean_dist(temp_ct, sample_ct, euc_dist, encoder, evaluator, gal_keys, relin_keys);
    }


    return 0;
}