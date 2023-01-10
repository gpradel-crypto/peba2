# peba2

The PEBA2 protocol is a privacy-preserving authentication protocol based on biometrics and homomorphic encryption (HE).
PEBA2 is [Apache licensed](https://github.com/lab-incert/peba-seal/blob/main/LICENSE) and has been developed by Gaëtan Pradel, member of the R&D Department of [INCERT](https://www.incert.lu/), based in Luxembourg and PhD Candidate at the Information Security Group in Royal Holloway, University of London under the supervision of [Prof. Chris Mitchell](https://www.chrismitchell.net/).

In PEBA2, the HE scheme used is CKKS [1] as implemented by Microsoft in their open-source library Microsoft SEAL [2].

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
