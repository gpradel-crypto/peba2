

#include <fstream>
#include "homomorphic_math.h"
#include "plain_math.h"
#include "utilities.h"
#include "accuracy.h"

#define TRIALS 100

void ckks_for_accuracy(std::ofstream &file_output_results){
    /*
     *
     * Protocol P execution for accuracy!
     *  202,509 images from "Deep Learning Face Attributes in the Wild
     */

    file_output_results << " A subversion of the protocol P with CKKS will be executed to verify the accuracy of it." << std::endl;
    file_output_results << " Useless operations for that purpose, e.g. digital signature, are not computed for faster computation." << std::endl << std::endl;

    file_output_results << " Initialisation of the parameters. Done only one time" << std::endl;
    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree,{60, 40, 40, 40, 40, 40,40, 40, 40, 40, 40, 40,40, 40, 40, 40, 40, 40,40, 40, 60}));

    const std::vector<int> bitsizes = {60, 40, 40, 40, 40, 40, 40, 40, 40, 40,40, 40, 40, 40, 40, 40, 40, 40, 40, 40,60};

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
        std::string filename = "../keys/secret_ckks_acc.key";
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
        std::string filename = "../keys/public_ckks_acc.key";
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
        std::string filename = "../keys/relin_ckks_acc.key";
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
        std::string filename = "../keys/galois_ckks_acc.key";
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

    // std::string path = "../celeba_arrays/"; // for the celeba dataset
    std::string path = "../pict_arrays/"; // for testing on the known dataset
    std::ifstream reader;
    std::vector<std::vector<double>> templates;
    std::vector<std::string> mapping_index_file_name;
    std::ofstream file_mapping("../mapping_index_file_name.data");
    int cnt_file=0;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of doubles", file_output_results, 1, Unit::millisecs);
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
    int result_accuracy = 0; // for the accuracy
    file_output_results << "The protocol P will be executed " << TRIALS << " times." <<  std::endl;
    for (int i = 0; i < TRIALS; ++i) {
        //we choose randomly two vectors from the database
        int which_sample = RandomIndexForImage(cnt_file-1);
        int which_template = RandomIndexForImage(cnt_file-1);
        while (which_sample == which_template)
            which_template = RandomIndexForImage(cnt_file-1);

        file_output_results << std::endl << "Execution of P with CKKS number " << i+1 << " between:" << std::endl;
        file_output_results << "Vector: " << which_sample+1 << " starting by " << templates[which_sample][0] << std::endl;
        file_output_results << "Vector: " << which_template+1 << " starting by " << templates[which_template][0] << std::endl;


        seal::Ciphertext euc_dist_ct;
        enc_euclidean_dist(templates_ct[which_sample], templates_ct[which_template], euc_dist_ct, encoder,
                               evaluator, gal_keys, relin_keys, scale);

        std::vector<double> bound(dimension, 0.3);
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
    file_output_results << std::endl << "Over " << TRIALS << " executions of P, " << result_accuracy << " were successful." << std::endl;
    file_output_results << "The accuracy is thus of " << ((1.0*result_accuracy)/TRIALS)*100.0 << "%." <<  std::endl;
    auto end_time_P_execution = std::chrono::high_resolution_clock::now();
    auto duration_P_execution = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_P_execution - start_time_P_execution);
    file_output_results << "All the executions of P were executed in " << duration_P_execution.count()/1000.0 << " seconds." << std::endl;
}

void bfv_for_accuracy(std::ofstream &file_output_results){
    /*
     *
     * Protocol P execution for accuracy!
     *  202,509 images from "Deep Learning Face Attributes in the Wild
     */

    file_output_results << " A subversion of the protocol P with BFV will be executed to verify the accuracy of it." << std::endl;
    file_output_results << " Useless operations for that purpose, e.g. digital signature, are not computed for faster computation." << std::endl << std::endl;

    file_output_results << " Initialisation of the parameters. Done only one time" << std::endl;
    auto start_time_params = std::chrono::high_resolution_clock::now();
    //Creation of the homomorphic keys
    // Seal encryption set up
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 60));

    //Slot dimension
    int quantisation_bits = 2; // cannot be higher than 25 with the highest SEAL parameters

    file_output_results << "\t\t --- Information about computations ---" << std::endl;
    seal::SEALContext context(parms);
    int64_t scaling_factor = FindPowerOfTen(quantisation_bits);

    PrintParametersSEAL(context, file_output_results, 0, scaling_factor);

    //Set up the keys
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key;
    {
        std::string filename = "../keys/secret_bfv_acc.key";
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
        std::string filename = "../keys/public_bfv_acc.key";
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
        std::string filename = "../keys/relin_bfv_acc.key";
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
        std::string filename = "../keys/galois_bfv_acc.key";
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
    file_output_results << "Parameters and keys were set in " << duration_params.count()/1000.0 << " seconds." << std::endl;

    auto start_time_enc_data = std::chrono::high_resolution_clock::now();

    // std::string path = "../celeba_arrays/"; // for the celeba dataset
    std::string path = "../pict_arrays/"; // for testing on the known dataset
    std::ifstream reader;
    std::vector<std::vector<double>> templates;
    std::vector<std::vector<int64_t>> templates_int;
    std::vector<std::string> mapping_index_file_name;
    std::ofstream file_mapping("../mapping_index_file_name.data");
    int cnt_file=0;
    {
        Stopwatch sw("Reading encoded pictures files and transforming them in vectors of doubles", file_output_results, 1, Unit::millisecs);
        for (const auto &file: std::filesystem::directory_iterator(path)) {
            //the if is only there to avoid to parse the ".gitkeep" file, more robust solutions would be preferable
            if (file.path().string().find(".gitkeep") == std::string::npos) {
                cnt_file+=1;
                mapping_index_file_name.push_back(file.path().string());
                file_mapping << cnt_file << "\t" << file.path().string() << std::endl;
                std::vector<double> tmp_vect = ParseEncoding(reader, file.path());
                FillVectorUntilN(tmp_vect, encoder.slot_count(), 0.0);
                templates.push_back(tmp_vect);
                templates_int.push_back(MapDoublesToIntegers(tmp_vect, scaling_factor));
            }
        }
    }
    file_mapping.close();

    // Encryption of the template
    std::vector<seal::Plaintext> templates_pt;
    {
        Stopwatch sw("Encoding of the templates as plaintexts",
                     file_output_results, 1, Unit::millisecs);
        seal::Plaintext temp_pt;
        for (int i = 0; i < templates.size(); ++i) {
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

    auto end_time_enc_data = std::chrono::high_resolution_clock::now();
    auto duration_enc_data = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_enc_data - start_time_enc_data);
    file_output_results << "The database of encoded pictures was encrypted in " << duration_enc_data.count()/1000.0 << " seconds." << std::endl;

    auto start_time_P_execution = std::chrono::high_resolution_clock::now();
    file_output_results << std::endl <<"  ----------- Computation phase --------------" << std::endl;
    int result_accuracy = 0; // for the accuracy
    file_output_results << "The protocol P will be executed " << TRIALS << " times." <<  std::endl;
    for (int i = 0; i < TRIALS; ++i) {
        //we choose randomly two vectors from the database
        int which_sample = RandomIndexForImage(cnt_file-1);
        int which_template = RandomIndexForImage(cnt_file-1);
        while (which_sample == which_template)
            which_template = RandomIndexForImage(cnt_file-1);

        file_output_results << std::endl << "Execution of P with BFV number " << i+1 << " between:" << std::endl;
        file_output_results << "Vector: " << which_sample+1 << " starting by " << templates_int[which_sample][0] << std::endl;
        file_output_results << "Vector: " << which_template+1 << " starting by " << templates_int[which_template][0] << std::endl;


        seal::Ciphertext euc_dist_ct;
        enc_euclidean_dist_bfv(templates_ct[which_sample], templates_ct[which_template], euc_dist_ct, encoder,
                               evaluator, gal_keys, relin_keys);

        std::vector<double> bound(encoder.slot_count(), 0.3);
        int64_t squared_scaling_factor = scaling_factor*scaling_factor;
        std::vector<int64_t> bound_int = MapDoublesToIntegers(bound, squared_scaling_factor); //scaling factor is squared because the result of the Euclidean distance does not have the square root

        seal::Plaintext bound_pt;
        seal::Ciphertext bound_ct;
        encoder.encode(bound_int, bound_pt);
        encryptor.encrypt(bound_pt, bound_ct);
        evaluator.mod_switch_to_inplace(bound_ct, euc_dist_ct.parms_id());
        evaluator.sub_inplace(bound_ct, euc_dist_ct);


        std::vector<int64_t> tau (128, RandomLongInt());

        // Server creates the plaintext for Tau
        seal::Plaintext tau_pt;
        encoder.encode(tau, tau_pt);
        evaluator.multiply_plain_inplace(bound_ct, tau_pt);

        seal::Plaintext token_pt;
        std::vector<int64_t> token;
        decryptor.decrypt(bound_ct, token_pt);
        encoder.decode(token_pt, token);


        //Protocol P executed as if it would be on cleartexts
        bool true_P = false;
        int64_t euc_dist_true = euclidean_distance_int(templates_int[which_sample], templates_int[which_template]);
        if (euc_dist_true < bound_int[0])
            true_P = true;
        file_output_results << "The square euclidean distance is equal to " << euc_dist_true << std::endl;
        file_output_results << "The authentication shall ";
        if (true_P)
            file_output_results << "succeed." << std::endl;
        else
            file_output_results << "fail." << std::endl;

        bool he_P = false;
        //Given it is an approximate calculus, we accepted the following error in the computation for the acceptance of the token

        if ((token[0] == 0) || (token[0]%tau[0] != 0) || (token[0] < 0)) {
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
    file_output_results << std::endl << "Over " << TRIALS << " executions of P, " << result_accuracy << " were successful." << std::endl;
    file_output_results << "The accuracy is thus of " << ((1.0*result_accuracy)/TRIALS)*100.0 << "%." <<  std::endl;
    auto end_time_P_execution = std::chrono::high_resolution_clock::now();
    auto duration_P_execution = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_P_execution - start_time_P_execution);
    file_output_results << "All the executions of P were executed in " << duration_P_execution.count()/1000.0 << " seconds." << std::endl;
}