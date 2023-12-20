# About this repository

For theoretical details, please refer to [Extraction Algorithm](https://eprint.iacr.org/2020/015.pdf), most code is borrowed from [Secretflow spu](https://github.com/secretflow/spu/tree/main/libspu/mpc/cheetah/rlwe).


# Complie and Install SEAL
For details, please refer to [Microsoft SEAL](https://github.com/microsoft/SEAL/tree/main), the following will show how to compile and install SEAL in Ubuntu.

```Bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build
```
If download breaks when running cmake -S . -B build, use the following command instead

```Bash
cmake -S . -B build  -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
```

If all the command runs successfully, SEAL is compiled and installed globally.

# Compile and test this repository
After git clone and moving to the downloaded folder, run the following command to install

```bash
cmake -S . -B build
cmake --build build
```

For test, please run

```bash
cd build
make test
```