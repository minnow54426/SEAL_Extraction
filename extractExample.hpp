#pragma once
#include "util.hpp"


uint64_t extract_example(std::size_t index, std::size_t value) {
    seal::EncryptionParameters parms(seal::scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    seal::SEALContext context(parms);
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);

    // Place value in index, which will be extracted soon, just for verification
    index = 3;
    value = 546465; 
    seal::Plaintext pt(poly_modulus_degree);
    *(pt.data() + index) = value;

    // Encrypt
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);
    // Switch until only one modulu is left
    // This step must be done before extracion
    evaluator.mod_switch_to_next_inplace(ct); 

    // Extract
    LWECT lwe_ct = LWECT(ct, index, context); 

    // Decrypt
    lweSecretKey lwe_sk = lweSecretKey(secret_key, context);
    lweDecryptor lwe_decryptor = lweDecryptor(lwe_sk, context, parms);
    uint64_t result = lwe_decryptor.DoDecrypt(lwe_ct);

    std::cout << result << std::endl;

    return result;
}
