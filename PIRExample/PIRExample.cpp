#include "PIRExample.h"



void PIRExample(std::size_t index, std::size_t database_size) {
    // Index indicates the data we want to retrieval from database, begins from 0
    // Assuming that database_size is not larger than poly_modulus_degree
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
    encryptor.set_secret_key(secret_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);

    // Set plaintext value, the value in index is 1, others are 0
    // Used for query
    seal::Plaintext pt(poly_modulus_degree);
    *(pt.data() + index) = 1;
    seal::Ciphertext query;

    // Generate a random database, according to plaintext modulus
    uint64_t plain_modulus = parms.plain_modulus().value();
    std::vector<std::size_t> database(database_size);
    std::generate(database.begin(), database.end(), random_generator<int>(plain_modulus));
    // Plaintext used for store database
    seal::Plaintext database_pt(poly_modulus_degree);

    // LWE secretkey and decryptor
    lweSecretKey lwe_secretkey = lweSecretKey(secret_key, context);
    lweDecryptor lwe_decryptor = lweDecryptor(lwe_secretkey, context, parms);

    // Time recoder
    std::chrono::high_resolution_clock::time_point start_time, end_time;

    // The structure follows fastPIR, see https://github.com/ishtiyaque/FastPIR/blob/master/src/main.cpp
    // 1. Preprocess database
    // 2. Generate query
    // 3. Generate response
    // 4. Retrieval data from response

    // 1. Preprocess database, just place the element in plaintext according to the mapping
    // Note: plaintext can be generated before this procedure
    start_time = std::chrono::high_resolution_clock::now();
    auto reverse_ptr = std::reverse_iterator<uint64_t*>(database_pt.data() + poly_modulus_degree + 1);
    std::copy_n(database.begin(), database_size, reverse_ptr);
    end_time = std::chrono::high_resolution_clock::now();
    auto data_preporcess_time = (std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time)).count();
    std::cout << "Preprocessing of database is done." << std::endl << std::endl;

    // 2. Generate query, encrypt plaintext
    start_time = std::chrono::high_resolution_clock::now();
    encryptor.encrypt_symmetric(pt, query);
    // To minimun the query size, modulus switch is applied
    end_time = std::chrono::high_resolution_clock::now();
    auto generate_query_time = (std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time)).count();
    std::cout << "Generating of query is done.";
    std::cout << "Query size is: " << 2 * query.poly_modulus_degree() * query.coeff_modulus_size() * 8 << " bytes";
    std::cout << std::endl << std::endl;

    // 3. Generate response, ciphertext(query) times plaintext(database), and then extract
    start_time = std::chrono::high_resolution_clock::now();
    evaluator.multiply_plain_inplace(query, database_pt);
    evaluator.mod_switch_to_next_inplace(query);
    LWECT response = LWECT(query, 0, context); // According to database mapping, extraction index is always zero
    end_time = std::chrono::high_resolution_clock::now();
    auto generate_response_time = (std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time)).count();
    std::cout << "Generating of response is done.";
    std::cout << "Response size is: " << query.poly_modulus_degree() * query.coeff_modulus_size() * 8 + 8 << " bytes";
    std::cout << std::endl << std::endl;

    // 4. Retrieval data from response
    start_time = std::chrono::high_resolution_clock::now();
    uint64_t data = lwe_decryptor.DoDecrypt(response);
    // Negate 
    data = seal::util::negate_uint_mod(data, parms.plain_modulus());
    end_time = std::chrono::high_resolution_clock::now();
    auto retrieval_data_time = (std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time)).count();
    std::cout << "Retrievaling of data is done." << std::endl << std::endl;

    // Correctness check
    std::cout << std::endl;
    std::cout << "The plain modulus is : " << plain_modulus << std::endl;
    std::cout << "The actual data we want to extract is: " << database[index] << std::endl;
    std::cout << "The retrieval result is: " << data << std::endl;

    // Time
    std::cout << std::endl;
    std::cout << "Proprocessing of database: " << data_preporcess_time << std::endl;
    std::cout << "Generating of query: " << generate_query_time << std::endl;
    std::cout << "Generating of response: " << generate_response_time << std::endl;
    std::cout << "Retrievaling of data: " << retrieval_data_time << std::endl;

}
