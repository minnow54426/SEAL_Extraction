#ifndef UTIL_H
#define UTIL_H

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <random>
#include <vector>


class LWECT {
private:
	seal::Plaintext ct1; // ct1
	uint64_t ct0; // ct0, if modulus switch is applied, only one modulus is left
	std::size_t poly_modulus_degree_{ 0 }; // length of every single polynomial

public:
    // Construct LWE ciphertext from RLWE ciphertext
    // coeff_index represents the index to be extracted
    LWECT(const seal::Ciphertext& RLWECT, const std::size_t coeff_index,
	const seal::SEALContext& context);
    // Some useful help functions
	inline const std::size_t poly_modulus_degree() const { return poly_modulus_degree_; };
	inline seal::parms_id_type parms_id() const { return ct1.parms_id(); };
	inline const double scale() { return ct1.scale(); };
	inline const uint64_t get_ct0() const { return ct0; };
	inline const seal::Plaintext get_ct1() const { return ct1; };
};

class lweSecretKey {
private:
    // Store secretkey in non-ntt form, because only inner product will applied 
	seal::SecretKey secret_non_ntt_;

public:
	lweSecretKey(const seal::SecretKey& rlwe_sk, const seal::SEALContext& context);

	seal::SecretKey& get_sk() { return secret_non_ntt_; };
};

class lweDecryptor {
private:
	lweSecretKey sk_;
	seal::SEALContext context_;
    seal::EncryptionParameters encryption_parms_;

public:
	lweDecryptor(const lweSecretKey& sk, const seal::SEALContext& context, const seal::EncryptionParameters encryption_parms)
		: sk_(sk), context_(context), encryption_parms_(encryption_parms) {
            // Seal's copy constructor is enough
        };

	uint64_t DoDecrypt(const LWECT& ct);
};

#endif
