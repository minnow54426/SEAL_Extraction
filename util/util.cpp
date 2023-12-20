#include "util.h"


LWECT::LWECT(const seal::Ciphertext& RLWECT, const std::size_t coeff_index,
	const seal::SEALContext& context) {
	// Read parameters
	std::size_t num_coeff = RLWECT.poly_modulus_degree(); 
	poly_modulus_degree_ = num_coeff;
	std::shared_ptr<const seal::SEALContext::ContextData> context_data =
	    context.get_context_data(RLWECT.parms_id()); // context data
	const seal::EncryptionParameters& parms = context_data->parms(); 
	const seal::Modulus& modulus = parms.coeff_modulus()[0]; 

	// Read data from RLWE ciphertext, write to LWE ciphertext after transformation
    // The resize function will check whether ciphertext is ntt form firstly, which
    // checks if parms_id is parms_id_zero, so following operations is needed
	ct1.parms_id() = seal::parms_id_zero; 
	ct1.resize(num_coeff * 1); // The number of modulus is 1
	ct1.parms_id() = RLWECT.parms_id();
	uint64_t* destination_ptr = ct1.data(); // Iterator points to head of ct1
	const seal::Ciphertext::ct_coeff_type* source_ptr = RLWECT.data(1); // Iterator points to head of c1

	// Extraction, see https://www.wolai.com/pxxu1LrqTjXTVbcN98aH6U for details
    auto reverse_ptr = std::reverse_iterator<uint64_t*>(destination_ptr + coeff_index + 1);
	std::copy_n(source_ptr, coeff_index + 1, reverse_ptr);
	// Reverse and negate coefficients in index [coeff_index + 1, num_coeff]
	reverse_ptr = std::reverse_iterator<uint64_t*>(destination_ptr + num_coeff);
	std::transform(
		source_ptr + coeff_index + 1, source_ptr + num_coeff, reverse_ptr,
		[&](uint64_t u) {
			return seal::util::negate_uint_mod(u, modulus);
		}
	);
	ct0 = RLWECT.data(0)[coeff_index];

	ct1.parms_id() = RLWECT.parms_id();
    // The following code is useful to CKKS only, so we will omit it
	// ct1.scale() = RLWECT.scale();
    }

lweSecretKey::lweSecretKey(const seal::SecretKey& rlwe_sk, const seal::SEALContext& context) {
	const seal::EncryptionParameters& parms = context.key_context_data()->parms();
	const std::vector<seal::Modulus>& modulus = parms.coeff_modulus();
	const std::size_t num_coeff = parms.poly_modulus_degree();
	const std::size_t num_modulus = modulus.size();

	secret_non_ntt_.data().parms_id() = seal::parms_id_zero;
	secret_non_ntt_.data().resize(num_coeff * num_modulus);
	secret_non_ntt_.data().parms_id() = rlwe_sk.parms_id();

	std::copy_n(rlwe_sk.data().data(), num_coeff * num_modulus, secret_non_ntt_.data().data());

	if (rlwe_sk.data().is_ntt_form()) {
		// Transform to non-ntt form
		const auto* ntt_tables = context.key_context_data()->small_ntt_tables();
		auto* sk_ptr = secret_non_ntt_.data().data();
		for (size_t l = 0; l < num_modulus; l++, sk_ptr += num_coeff) {
			seal::util::inverse_ntt_negacyclic_harvey(sk_ptr, ntt_tables[l]);
		}
	}
};

uint64_t lweDecryptor::DoDecrypt(const LWECT& ct) {
	std::size_t num_coeff = ct.poly_modulus_degree();

	std::shared_ptr<const seal::SEALContext::ContextData> context_data = context_.get_context_data(ct.parms_id());
	const seal::Modulus& modulus = context_data->parms().coeff_modulus()[0];
		
	// Calculate c0 + c1 * s
    // If modulus switch is applied, only one modulu is left
    uint64_t result;
	const uint64_t* op0 = sk_.get_sk().data().data();
	const uint64_t* op1 = ct.get_ct1().data();
    result = seal::util::dot_product_mod(op0, op1, num_coeff, modulus);
	result = seal::util::add_uint_mod(result, ct.get_ct0(), modulus);

    // Times t/Q
    seal::Modulus plain_modulus = encryption_parms_.plain_modulus(); // t
    seal::Modulus last_modulus = encryption_parms_.coeff_modulus()[0]; // Q
    // Plus 0.5, round will become floor 
    result = static_cast<int>(static_cast<double>(result * plain_modulus.value()) / last_modulus.value() + 0.5);

	return result;

	// If modulus switch is applied before tranfromation from RLWE ciphertext to LWE ciphertext, 
	// CRT is no longer needed, for usage, see https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/rns.cpp
	}
