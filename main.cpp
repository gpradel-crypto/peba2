#include <filesystem>
#include <fstream>
#include <seal/seal.h>
#include "src/utilities.h"
#include "src/protocol_ckks.h"
#include "src/protocol_bfv.h"









int main() {

    bool bfv = true;
    bool ckks = false;
    bool bgv = false;

    //File in which the results of the protocol p will be written
    if(bfv) {
        std::string file_path_bfv = "../results_bfv.data";
        std::ofstream file_output_results(file_path_bfv);

        //Time of the full suite of tests
        auto start_time_full = std::chrono::high_resolution_clock::now();
        protocol_p_bfv(file_output_results);
        auto end_time_full = std::chrono::high_resolution_clock::now();
        auto duration_full = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_full - start_time_full);

        file_output_results << std::endl << "The full protocol has taken " << duration_full.count()/1000.0 << " seconds." << std::endl;
        file_output_results.close();
        std::ifstream file_output_results_display;
        file_output_results_display.open(file_path_bfv);
        PrintFile(file_output_results_display);
        file_output_results_display.close();
    }

    if (ckks) {
        std::string file_path_ckks = "../results_ckks.data";
        std::ofstream file_output_results(file_path_ckks);
        //Time of the full suite of tests
        auto start_time_full = std::chrono::high_resolution_clock::now();
        protocol_p(file_output_results);
        auto end_time_full = std::chrono::high_resolution_clock::now();
        auto duration_full = std::chrono::duration_cast<std::chrono::milliseconds >(end_time_full - start_time_full);
        file_output_results << std::endl << "The full protocol has taken " << duration_full.count()/1000.0 << " seconds." << std::endl;

        file_output_results.close();
        std::ifstream file_output_results_display;
        file_output_results_display.open(file_path_ckks);
        PrintFile(file_output_results_display);
        file_output_results_display.close();
    }


    //File in which the results of the accuracy of the protocol p will be written
//    std::ofstream file_accuracy("../results_accuracy.data");
//    protocol_p_for_accuracy(file_accuracy);
//    file_accuracy.close();

    return EXIT_SUCCESS;
}