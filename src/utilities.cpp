//
// Created by gpr on 16/03/2022.
//

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
void PrintParametersSEAL(const seal::SEALContext &context, std::ofstream& file_name, int power_of_scale)
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
        default:
            throw std::invalid_argument("unsupported scheme");
    }
    file_name << "/" << std::endl;
    file_name << "| Encryption parameters :" << std::endl;
    file_name << "|   scheme: " << scheme_name << std::endl;
    file_name << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
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
    seal::CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    file_name << "|   Number of slots (dimension of vectors): " << slot_count << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        file_name << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    file_name << "|    Scale: 2^" << power_of_scale << std::endl;
    file_name << "|    Number of rescaling allowed: " << coeff_modulus_size
                        << std::endl;
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

