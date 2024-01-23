#include "extractExample/extractExample.h"
#include "PIRExample/PIRExample.h"




void test_tranfrom_between_lwect_ptv() {
    std::size_t index = 5;
    std::size_t value = 6;

    seal::Modulus PRIME_60 = seal::Modulus(1152921504606830593ULL);
    seal::Modulus PRIME_49 = seal::Modulus(562949953216513ULL);
    std::vector<seal::Modulus> COEFF_MOD_ARR{PRIME_60, PRIME_49};

    uint64_t PLAIN_MODULUS = 1073153;
    std::size_t POLY_MODULUS_DEGREE = 4096;

    seal::EncryptionParameters parms(seal::scheme_type::bfv);

    parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    parms.set_coeff_modulus(COEFF_MOD_ARR);
    parms.set_plain_modulus(PLAIN_MODULUS);
    seal::SEALContext context(parms);
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);

    // Place value in index, which will be extracted soon, just for verification
    seal::Plaintext pt(POLY_MODULUS_DEGREE);
    *(pt.data() + index) = value;

    // Encrypt
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);


    // Extract
    LWECT lwe_ct = LWECT(ct, index, context); 

    // Transform lwect to plaintext vector

    std::vector<seal::Plaintext> ptv = lwe_ct.to_pt();


    // Transform back
    ptv_to_lwect(ptv, lwe_ct);

    // Decrypt
    lweSecretKey lwe_sk = lweSecretKey(secret_key, context);
    lweDecryptor lwe_decryptor = lweDecryptor(lwe_sk, context, parms);
    uint64_t result = lwe_decryptor.DoDecrypt(lwe_ct);

    std::cout << value << std::endl;

    std::cout << result << std::endl;
}

int main() {
    // Extract an LWE ciphertext from RLWE ciphertext from index 3, whose value is 4
    // extract_example(3, 4);
    // The first parameter is retrievaled index from database, begins from 0
    // and must be smaller than plaintext polynomial length
    // The second parameter is length of database
    // PIRExample(5, 100);

    test_tranfrom_between_lwect_ptv();
    return 0;
}