#ifndef THREATS_SEAL_PLAIN_MATH_H
#define THREATS_SEAL_PLAIN_MATH_H


double manhattan_distance(std::vector<double> v1, std::vector<double> v2);

double euclidean_distance(std::vector<double> v1, std::vector<double> v2);

int64_t euclidean_distance_int(std::vector<int64_t> v1, std::vector<int64_t> v2);

void final_approx_inplace(double& x);

double f1(double x);

double f2(double x);

double f3(double x);

double f4(double x);

double g1(double x);

double g2(double x);

double g3(double x);

double g4(double x);

int64_t Lagrange_257(int64_t x);

#endif //THREATS_SEAL_PLAIN_MATH_H
