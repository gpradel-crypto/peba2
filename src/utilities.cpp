//
// Created by gpr on 16/03/2022.
//

#include <random>
#include <seal/seal.h>
#include "utilities.h"
using namespace std;

double random_double(void) {
    random_device rd;
    default_random_engine engine(rd());
    uniform_real_distribution<double> distrib(LOWER_BOUND, UPPER_BOUND);
    return distrib(engine);
}


vector<double> create_vector_input(size_t dimension) {
    vector<double> results;
    results.reserve(dimension);
    for (size_t i  = 0; i < dimension ; i++) {
        srand(i);
        double r = random_double();
        results.push_back(r);
    };
    return results;
}

vector<double> create_vector_input_chosen(size_t dimension, double value) {
    vector<double> results;
//    results.reserve(dimension);
    for (size_t i  = 0; i < dimension ; i++) {
        results.push_back(value);
    };
    return results;
}

void print_vector(vector<double> vect) {
    cout << "[ ";
    for (int i = 0; i < vect.size(); i++) {
        cout << vect[i] << " ";
    }
    cout << "]";
    cout << endl;
}


/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(const seal::SEALContext &context)
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
    cout << "/" << std::endl;
    cout << "| Encryption parameters :" << std::endl;
    cout << "|   scheme: " << scheme_name << std::endl;
    cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "|   coeff_modulus size: ";
    cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        cout << coeff_modulus[i].bit_count() << " + ";
    }
    cout << coeff_modulus.back().bit_count();
    cout << ") bits" << std::endl;
    seal::CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "|   Number of slots: " << slot_count << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

//    cout << "\\" << std::endl << std::endl;
}
