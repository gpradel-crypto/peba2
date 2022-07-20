# threats-seal

The PEBA protocol is a privacy-preserving authentication protocol based on biometrics and homomorphic encryption (HE).

Here, the HE scheme used is CKKS [1], as implemented by Microsoft in their open-source library Microsoft SEAL [2].

## Dependencies


### Linux Ubuntu
Microsoft SEAL must be installed from their source [2].

Python and pip are required for getting the encoding of the biometrics which here are human faces.
The face_recognition library [3] is used.

#### pip

pip3 install face_recognition

#### apt
On top of Microsoft SEAL dependencies, the following are required.
sudo apt install libssl-dev 




## References

[1] Jung Hee Cheon and Dongwoo Kim and Duhyeong Kim, Efficient Homomorphic Comparison Methods with Optimal Complexity, 2019, Cryptology ePrint Archive, Paper 2019/1234, https://eprint.iacr.org/2019/1234}

[2] Microsoft SEAL release 4.0, {https://github.com/Microsoft/SEAL}, 2022

[3] https://github.com/ageitgey/face_recognition
