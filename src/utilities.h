#ifndef THREATS_SEAL_UTILITIES_H
#define THREATS_SEAL_UTILITIES_H

#include <iostream>
#include <chrono>
#include <vector>
#include <filesystem>


constexpr double LOWER_BOUND = -1.0;
constexpr double UPPER_BOUND = 1.0;

enum Unit {
    microsecs,
    millisecs,
    secs
};

class Stopwatch
{
public:
    Stopwatch(std::string timer_name, std::ofstream& file_name, std::size_t iterations, Unit unit) :
            name_(timer_name),
            start_time_(std::chrono::high_resolution_clock::now()),
            file_name_(file_name),
            iterations_(iterations),
            unit_(unit) //
    {
    }

    ~Stopwatch()
    {
        double it = static_cast<double>(iterations_);
        auto end_time = std::chrono::high_resolution_clock::now();
        if (unit_ == Unit::microsecs){
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
            file_name_ << name_ << "\t" << duration.count()/it << "\tmicroseconds" << std::endl;
        }
        if (unit_ == Unit::millisecs){
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
            file_name_ << name_ << "\t" << duration.count()/it << "\tmilliseconds" << std::endl;
        }
        if (unit_ == Unit::secs){
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
            file_name_ << name_ << "\t" << duration.count()/(it*1000.0) << "\tseconds" << std::endl;
        }
    }

private:
    std::string name_;
    std::chrono::high_resolution_clock::time_point start_time_;
    std::ofstream& file_name_;
    std::size_t iterations_;
    Unit unit_;
};


void PrintVector(std::vector<double> vect);
void PrintVectorInt(std::vector<int64_t> vect);
void PrintVectorUntilN(std::vector<double> vect, int n);
void PrintVectorIntUntilN(std::vector<int64_t> vect, int n);
void PrintVectorFile(std::vector<double> vect, std::ofstream& file_name);
void PrintVector2(std::vector<std::vector<double>> vect);
void PrintVector2Int(std::vector<std::vector<uint64_t>> vect);
void PrintVector2UntilN(std::vector<std::vector<double>> vect, int n);
void PrintVector2File(std::vector<std::vector<double>> vect, std::ofstream& file_name);
void PrintVector2FileUntilN(std::vector<std::vector<double>> vect, std::ofstream& file_name, int n);
void PrintParametersSEAL(const seal::SEALContext &context, std::ofstream& file_name, int power_of_scale, uint64_t rescaling_factor);
std::vector<double> TransformVectorsToVector(std::vector<std::vector<double>> v);
int RandomIndexForImage(int n);
double RandomDouble(void);
std::vector<double> CreateVectorInput(size_t dimension);
std::vector<double> CreateVectorInputChosen(size_t dimension, double value);
void FillVectorUntilN(std::vector<double>& input, int dimension, double value);
std::vector<char> FromFileToVect(std::string filename);
std::vector<double> ParseEncoding(std::ifstream& reader, std::filesystem::path file_path);
void PrintFile(std::ifstream& reader);
int64_t FindPowerOfTen (int power_of_2);
std::int64_t MapDoubleToInteger(double x, int64_t scaling_factor, int quantisation_bits);
std::vector<std::int64_t> MapDoublesToIntegers(std::vector<double> &v_double, int64_t scaling_factor, int quantisation_bits);


#endif //THREATS_SEAL_UTILITIES_H
