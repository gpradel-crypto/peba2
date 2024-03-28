#include <random>
#include <seal/seal.h>
#include <fstream>
#include "utilities.h"

void PrintVector(std::vector<double> vect) {
    if (vect.empty()) {
        perror("Vector empty for print in stdout");
        abort();
    }
    std::cout << "[ ";
    for (int i = 0; i < vect.size()-1; i++) {
        std::cout << vect[i] << ", ";
    }
    std::cout << vect[vect.size()-1] << " ]";
    std::cout << std::endl << std::endl;
}

void PrintVectorInt(std::vector<int64_t> vect) {
    if (vect.empty()) {
        perror("Vector empty for print in stdout");
        abort();
    }
    std::cout << "[ ";
    for (int i = 0; i < vect.size()-1; i++) {
        std::cout << vect[i] << ", ";
    }
    std::cout << vect[vect.size()-1] << " ]";
    std::cout << std::endl << std::endl;
}

void PrintVectorUntilN(std::vector<double> vect, int n) {
    if (vect.empty()) {
        perror("Vector empty for print in stdout");
        abort();
    }
    std::cout << "[ ";
    for (int i = 0; i < n; i++) {
        std::cout << vect[i] << ", ";
    }
    std::cout << vect[n] << " ]";
    std::cout << std::endl << std::endl;
}

void PrintVectorIntUntilN(std::vector<int64_t> vect, int n) {
    if (vect.empty()) {
        perror("Vector empty for print in stdout");
        abort();
    }
    std::cout << "[ ";
    for (int i = 0; i < n-1; i++) {
        std::cout << vect[i] << ", ";
    }
    std::cout << vect[n-1] << " ]";
    std::cout << std::endl << std::endl;
}

void PrintVectorFile(std::vector<double> vect, std::ofstream& file_name) {
    if (vect.empty()) {
        perror("Vector empty for print in the file");
        abort();
    }
    file_name << "[ ";
    for (int i = 0; i < vect.size()-1; i++) {
        file_name << vect[i] << ", ";
    }
    file_name << vect[vect.size()-1] << " ]";
    file_name << std::endl;
}

void PrintVector2(std::vector<std::vector<double>> vect) {
    if (vect.empty()) {
        perror("Vector of vectors empty for print in stdout");
        abort();
    }
    for (int i = 0; i < vect.size(); ++i) {
        if (vect[i].empty()){
            perror("One of the vectors in the vector of vectors empty for print in stdout");
            abort();
        }
    }
    for (int i = 0; i < vect.size(); i++) {
        std::cout << "[ ";
        for (int j = 0; j < vect[i].size()-1; ++j) {
            std::cout << vect[i][j] << ", ";
        }
        std::cout << vect[i][vect[i].size()-1] << " ]" << std::endl;
    }
    std::cout << std::endl << std::endl;
}

void PrintVector2Int(std::vector<std::vector<uint64_t>> vect) {
    if (vect.empty()) {
        perror("Vector of vectors empty for print in stdout");
        abort();
    }
    for (int i = 0; i < vect.size(); ++i) {
        if (vect[i].empty()){
            perror("One of the vectors in the vector of vectors empty for print in stdout");
            abort();
        }
    }
    for (int i = 0; i < vect.size(); i++) {
        std::cout << "[ ";
        for (int j = 0; j < vect[i].size()-1; ++j) {
            std::cout << vect[i][j] << ", ";
        }
        std::cout << vect[i][vect[i].size()-1] << " ]" << std::endl;
    }
    std::cout << std::endl << std::endl;
}

void PrintVector2UntilN(std::vector<std::vector<double>> vect, int n) {
    if (vect.empty()) {
        perror("Vector of vectors empty for print in stdout");
        abort();
    }
    for (int i = 0; i < vect.size(); ++i) {
        if (vect[i].empty()){
            perror("One of the vectors in the vector of vectors empty for print in stdout");
            abort();
        }
    }
    for (int i = 0; i < vect.size(); i++) {
        std::cout << "[ ";
        for (int j = 0; j < n-1; ++j) {
            std::cout << vect[i][j] << ", ";
        }
        std::cout << vect[i][n-1] << " ]" << std::endl;
    }
    std::cout << std::endl << std::endl;
}

void PrintVector2File(std::vector<std::vector<double>> vect, std::ofstream& file_name) {
    if (vect.empty()) {
        perror("Vector of vectors empty for print in stdout");
        abort();
    }
    for (int i = 0; i < vect.size(); ++i) {
        if (vect[i].empty()){
            perror("One of the vectors in the vector of vectors empty for print in stdout");
            abort();
        }
    }
    for (int i = 0; i < vect.size(); i++) {
        file_name << "[ ";
        for (int j = 0; j < vect[i].size()-1; ++j) {
            file_name << vect[i][j] << ", ";
        }
        file_name << vect[i][vect[i].size()-1] << " ]" << std::endl;
    }
    file_name << std::endl << std::endl;
}

void PrintVector2FileUntilN(std::vector<std::vector<double>> vect, std::ofstream& file_name, int n) {
    if (vect.empty()) {
        perror("Vector of vectors empty for print in stdout");
        abort();
    }
    for (int i = 0; i < vect.size(); ++i) {
        if (vect[i].empty()){
            perror("One of the vectors in the vector of vectors empty for print in stdout");
            abort();
        }
    }
    for (int i = 0; i < vect.size(); i++) {
        file_name << "[ ";
        for (int j = 0; j < n-1; ++j) {
            file_name << vect[i][j] << ", ";
        }
        file_name << vect[i][n-1] << " ]" << std::endl;
    }
    file_name << std::endl << std::endl;
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void PrintParametersSEAL(const seal::SEALContext &context, std::ofstream& file_name, int power_of_scale, int64_t scaling_factor)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
        case seal::scheme_type::bfv:
            scheme_name = "BFV";
            break;
        case seal::scheme_type::ckks:
            scheme_name = "CKKS";
            break;
        case seal::scheme_type::bgv:
            scheme_name = "BGV";
            break;
        default:
            throw std::invalid_argument("unsupported scheme");
    }
    file_name << "/" << std::endl;
    file_name << "| Encryption parameters :" << std::endl;
    file_name << "|   scheme: " << scheme_name << std::endl;
    file_name << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;
    file_name << "|   Maximum allowed bits: " <<  seal::CoeffModulus::MaxBitCount(context_data.parms().poly_modulus_degree()) << std::endl;
    file_name << "|   coeff_modulus size: ";
    file_name << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        file_name << coeff_modulus[i].bit_count() << " + ";
    }
    file_name << coeff_modulus.back().bit_count();
    file_name << ") bits" << std::endl;

    /*
     * Print slots number and scale for the CKKS scheme
     */
    if (context_data.parms().scheme() == seal::scheme_type::ckks) {
        seal::CKKSEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        file_name << "|   Number of slots (dimension of vectors): " << slot_count << std::endl;
        file_name << "|    Scale: 2^" << power_of_scale << std::endl;
        file_name << "|    Number of rescaling allowed: " << coeff_modulus_size << std::endl;
    }

    /*
    For the BFV scheme print the plain_modulus parameters.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        file_name << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
        seal::BatchEncoder encoder(context);
        size_t slot_count = encoder.slot_count();
        file_name << "|   Number of slots (dimension of vectors): " << slot_count << std::endl;
        file_name << "|   Rescaling factor: " << scaling_factor << std::endl;
    }

    /*
    For the BGV scheme need to print the plain_modulus parameters. TO BE DONE
    */
    if (context_data.parms().scheme() == seal::scheme_type::bgv)
    {
        //empty for now
    }
    file_name << "\\" << std::endl << std::endl;
}

std::vector<double> TransformVectorsToVector(std::vector<std::vector<double>> v) {
    std::vector<double> result;
    for (int i = 0; i < v.size(); ++i) {
        for (int j = 0; j < v[i].size(); ++j) {
            result.push_back(v[i][j]);
        }
    }
    return result;
}

int RandomIndexForImage(int n) {
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> distrib(0, n);
    return distrib(engine);
}

double RandomDouble(void) {
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_real_distribution<double> distrib(LOWER_BOUND, UPPER_BOUND);
    return distrib(engine);
}

int64_t RandomLongInt(void) {
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int64_t> distrib(LOWER_BOUND_INT, UPPER_BOUND_INT);
    return distrib(engine);
}


std::vector<double> CreateVectorInput(size_t dimension) {
    std::vector<double> results;
    results.reserve(dimension);
    for (size_t i  = 0; i < dimension ; i++) {
        srand(i);
        double r = RandomDouble();
        results.push_back(r);
    };
    return results;
}

std::vector<double> CreateVectorInputChosen(size_t dimension, double value) {
    std::vector<double> results;
//    results.reserve(dimension);
    for (size_t i  = 0; i < dimension ; i++) {
        results.push_back(value);
    };
    return results;
}

void FillVectorUntilN(std::vector<double>& input, int dimension, double value){
    for (int i = input.size(); i < dimension; ++i) {
            input.push_back(value);
    }
}

std::vector<char> FromFileToVect(std::string filename){
    int i;
    char byte = 0;
    std::vector<char> bytes;

    std::ifstream reader(filename, std::ios::binary);
    if( ! reader ) {
        perror("Error opening input file");
        abort();
    }

    while (reader.get(byte)){
        bytes.push_back(byte);
    }
    reader.close();
    return bytes;
}

/*
 * Input: a vector of encoded features from a photo given by the Python face_recognition library.
 * Output: a vector of double that can be used by the SEAL library.
 */
std::vector<double> ParseEncoding(std::ifstream& reader, std::filesystem::path file_path) {
    reader.open(file_path);
    if (!reader) {
        perror("The reader could not open the file.");
        abort();
    }
    std::vector<double> results;
    char c;
    std::string buffer;
    while (!reader.eof()) {
        reader.get(c);
        switch (c) {
            case ',':
                results.push_back(std::stof(buffer));
                buffer.clear();
                break;
            case EOF:
                results.push_back(std::stof(buffer));
                buffer.clear();
                break;
            case '[':
                break;
            case ']':
                if (!buffer.empty()) {
                    results.push_back(std::stof(buffer));
                    buffer.clear();
                }
                break;
            default:
                buffer.push_back(c);
        }
    }
    reader.close();
    return results;
}

void PrintFile(std::ifstream& reader){
    std::string line ;
    for( int i = 0; ! reader.eof() ; i++ ) {
        getline( reader , line ) ;
        std::cout << line << std::endl ;
    }
}

int64_t FindPowerOfTen (int power_of_2) {
    int64_t power_of_ten = 1;
    int n = (int) pow(2, power_of_2);
    while (power_of_ten*10 < n)
        power_of_ten *= 10;
    // power_of_ten /= 10;
    return power_of_ten;
}

/* Map doubles to integer for performing the biometric matching over the integers using BFV
 *
 */

std::int64_t MapDoubleToInteger(double x, int64_t scaling_factor) {
    int64_t x_scaled_truncated = (int64_t) trunc(x*scaling_factor);
    // int64_t x_scaled_truncated_int64 = (int64_t) x_scaled_truncated;
    return x_scaled_truncated;
}

std::vector<std::int64_t> MapDoublesToIntegers(std::vector<double> &v_double, int64_t scaling_factor) {
    std::vector<std::int64_t> v_int;
    for (int i = 0; i < v_double.size(); ++i) {
        v_int.push_back(MapDoubleToInteger(v_double[i], scaling_factor));
    }
    return v_int;
}

void decrypt_decode_print_bfv_adhoc(seal::Ciphertext &ct, seal::BatchEncoder &encoder,
                          seal::Decryptor &decryptor, std::string message) {
    std::cout << message << std::endl;
    int until = 128;
    seal::Plaintext tmp_pt;
    std::vector<int64_t> tmp;
    decryptor.decrypt(ct, tmp_pt);
    encoder.decode(tmp_pt, tmp);
    std::cout << "[ ";
    for (int i = 0; i < until; i++) {
        std::cout << tmp[i] << ", ";
    }
    std::cout << tmp[until] << " ]";
    std::cout << std::endl << std::endl;
}

void test_how_many_bits_precision_left_BFV(seal::Ciphertext &ct, seal::Decryptor &decryptor, seal::Evaluator &evaluator, seal::BatchEncoder &encoder, seal::Encryptor &encryptor) {
    std::vector<int64_t> tmp(128, 2);
    seal::Plaintext tmp_pt;
    encoder.encode(tmp, tmp_pt);
    seal::Ciphertext tmp_ct;
    encryptor.encrypt(tmp_pt, tmp_ct);
    for (int i = 0; i < 20; i++) {
        std::cout << "Round " << i+1 << std::endl;
        decrypt_decode_print_bfv_adhoc(ct, encoder, decryptor, "The ciphertext decrypted is equal to: :");
        std::cout << " Noise budget in the ciphertext on Round: " << i+1 << "  " << decryptor.invariant_noise_budget(ct) << " bits" << std::endl;
        evaluator.multiply_plain_inplace(ct, tmp_pt);
    }
}

// char* int64ToChar(int64_t n) {
//     char* result = (char*) malloc(sizeof(int64_t));
//     memcpy(result, &n, 8);
//     return result;
// }
//
// int64_t charTo64bitNum(char a[]) {
//     int64_t n = 0;
//     memcpy(&n, a, 8);
//     return n;
// }
//
// void vector_int64_to_char(char a[], std::vector<int64_t> vect_n) {
//     for (int i = 0; i < vect_n.size(); ++i) {
//         a += int64ToChar(vect_n[i]);
//     }
// }
