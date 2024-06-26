# peba2

The PEBA2 protocol is a privacy-preserving authentication protocol based on biometrics and homomorphic encryption (HE).
PEBA2 is [Apache licensed](https://github.com/lab-incert/peba-seal/blob/main/LICENSE) and has been developed by Gaëtan Pradel, member of the R&D Department of [INCERT](https://www.incert.lu/), based in Luxembourg and PhD Candidate at the Information Security Group in Royal Holloway, University of London under the supervision of [Prof. Chris Mitchell](https://www.chrismitchell.net/).

In PEBA2, the HE schemes used are CKKS [1] and BFV [5,6] as implemented by Microsoft in their open-source library Microsoft SEAL [2].

Current version: 1.1


| Version      |                       Description                          | Date of release |
|--------------|------------------------------------------------------------|-----------------|
| 1.1          | Addition of the implementation of PEBA2 using BFV          |   27 March 2024 |
| 1.0          | Initial version of the implementation of PEBA2 using CKKS. |    19 July 2022 |

## Dependencies


### Linux Ubuntu
Microsoft SEAL must be installed from their source [2].

Python and pip are required for getting the encoding of the biometrics which here are human faces.

The face_recognition library [3] is used for the faces encoding.

#### pip
```
pip3 install face_recognition
```
#### apt
On top of Microsoft SEAL dependencies, the following ones are required.
```
sudo apt install libssl-dev 
```

To test our code, we used the Large-scale CelebFaces Attributes ([CelebA](https://drive.google.com/drive/folders/0B7EVK8r0v71pWEZsZE9oNnFzTm8?resourcekey=0-5BR16BdXnb8hVj6CNHKzLg)) Dataset By Multimedia Lab, The Chinese University of Hong Kong [4].


## References

[1] Jung Hee Cheon, Andrey Kim, Miran Kim and Yongsoo Song, *Homomorphic Encryption for Arithmetic of Approximate Numbers*, 2016, Cryptology ePrint Archive, Paper 2016/421, https://eprint.iacr.org/2016/421

[2] Microsoft SEAL release 4.0, https://github.com/Microsoft/SEAL, 2022

[3] https://github.com/ageitgey/face_recognition

[4] Ziwei Liu, Ping Luo, Xiaogang Wang, and Xiaoou Tang, *Deep Learning Face Attributes in the Wild*, 2015, Proceedings of International Conference on Computer Vision (ICCV)

[5] Z. Brakerski. Fully homomorphic encryption without modulus switching from classical gapsvp. In Advances in Cryptology — CRYPTO 2012 — 32nd Annual Cryptology Conference, Santa Barbara, CA, USA, August 19–23, 2012. Proceedings, pages 868–886, 2012.

[6] J. Fan and F. Vercauteren. Somewhat practical fully homomorphic encryption. Cryptology ePrint Archive, Paper 2012/144, 2012. https://eprint.iacr.org/2012/144.
