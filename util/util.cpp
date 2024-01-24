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
    uint64_t result{0};
	uint64_t modTemp{0};
	const uint64_t* op0 = sk_.get_sk().data().data();
	const uint64_t* op1 = ct.get_ct1().data();

	seal::Modulus plain_modulus = encryption_parms_.plain_modulus(); // t
	seal::Modulus last_modulus = encryption_parms_.coeff_modulus()[0]; // Q

	for (std::size_t i = 0; i < num_coeff; i++) {
		modTemp = seal::util::multiply_uint_mod(*(op0 + i), *(op1 + i), modulus);
		result = seal::util::add_uint_mod(result, modTemp, modulus);
	}

	// If fastPIR parameters is used, don't use this line, although it's faster
	// than above loop
    // result = seal::util::dot_product_mod(op0, op1, num_coeff, modulus);

	result = seal::util::add_uint_mod(result, ct.get_ct0(), modulus);

    // Times t/Q
	uint64_t resultTmp[2]{0, 0};
	seal::util::multiply_uint64(result, plain_modulus.value(), reinterpret_cast<unsigned long long*>(resultTmp)); // Times t
	uint64_t decrypt_result[2]{0, 0};
	uint64_t half_modulus = last_modulus.value() % 2 ? (last_modulus.value() - 1) / 2 : last_modulus.value() / 2; // Round
	seal::util::add_uint(resultTmp, 2, half_modulus, resultTmp); // After negate, sub becomes add, round
	seal::util::divide_uint128_inplace(resultTmp, last_modulus.value(), decrypt_result); // Divide Q, ceil function

	return decrypt_result[0];

	// If modulus switch is applied before tranformation from RLWE ciphertext to LWE ciphertext, 
	// CRT is no longer needed, for usage, see https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/rns.cpp
}

std::vector<seal::Plaintext> LWECT::to_pt() {
	std::vector<seal::Plaintext> result;

	// 1. Slice every 60 bits number into 3 20 bits number
	// 2. Transform 20 bits number to string
	// 3. Transfrom string to plaintext

	// Fristly, deal with ct0, whose type is uint64_t
	uint64_t least, middle, upper{};
	least = ct0 & 0xfffff;
	middle = (ct0 >> 20) & 0xfffff;
	upper = (ct0 >> 40) & 0xfffff;
	result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&least, std::size_t(1))));
	result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&middle, std::size_t(1))));
	result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&upper, std::size_t(1))));

	// Then deal with ct1, whose type is seal::Plaintext
	for (std::size_t i = 0; i < ct1.coeff_count(); i++) {
		least = ct1[i] & 0xfffff;
		middle = (ct1[i] >> 20) & 0xfffff;
		upper = (ct1[i] >> 40) & 0xfffff;
		result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&least, std::size_t(1))));
		result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&middle, std::size_t(1))));
		result.push_back(seal::Plaintext(seal::util::uint_to_hex_string(&upper, std::size_t(1))));
	}

	return result;
}

void ptv_to_lwect(std::vector<seal::Plaintext> ptv, LWECT lwe_ct) {
	// Read ct0 from plaintext vector
	uint64_t least, middle, upper{};
	least = *ptv[0].data();
	middle = *ptv[1].data();
	upper = *ptv[2].data();
	lwe_ct.set_ct0((upper << 40) + (middle << 20) + least);

	// Read ct1 from plaintext vector
	seal::Plaintext pt(ptv.size() / 3 - 1);
	for (int i = 3; i < ptv.size(); i += 3) {
		least = *ptv[i].data();
		middle = *ptv[i + 1].data();
		upper = *ptv[i + 2].data();
		*(pt.data() + (i / 3 - 1)) = (upper << 40) + (middle << 20) + least;
	}
	lwe_ct.set_ct1(pt);
}

std::vector<seal::Plaintext> lwe_ctv_to_ptv(std::vector<LWECT> lwe_ctv) {
	// Firstly, transform lwe_ctv into a 2 dimensional vector, 
	// where each element is a 20 bits num
	std::vector<std::vector<uint64_t>> lwe_ctv_decompose(lwe_ctv.size());
	uint64_t least, middle, upper{};
	for (int i = 0; i < lwe_ctv.size(); i ++) {
		for (int j = 0; j < lwe_ctv[0].get_ct1().coeff_count(); j++) {	
			uint64_t tmp = *(lwe_ctv[i].get_ct1().data() + j);
			least = tmp & 0xfffff;
			middle = (tmp >> 20) & 0xfffff;
			upper = (tmp >> 40) & 0xfffff;
			lwe_ctv_decompose[i].push_back(least);
			lwe_ctv_decompose[i].push_back(middle);
			lwe_ctv_decompose[i].push_back(upper);
		}
	}
	// Determine how many columns can be stored in a single plaintext
	std::size_t poly_length = lwe_ctv[0].get_ct1().coeff_count();
	std::size_t num = poly_length / lwe_ctv.size();
	// Determine the number of plaintext we need
	std::size_t pt_num = (3 * (poly_length + 1) / num) + 1;
	// Create the result container
	std::vector<std::vector<uint64_t>> result = std::vector(pt_num, std::vector<uint64_t>(poly_length));
	for (int i = 0; i < 3 * (poly_length + 1); i++) {
		// Determine the index of plaintext
		std::size_t pt_index = i / num;
		for (int j = 0; j < lwe_ctv.size(); j++) {
			result[pt_index].push_back(lwe_ctv_decompose[j][i]);
		}
	}
	// Transform the result container into plaintext vector
	std::vector<seal::Plaintext> ptv;
	for (int i = 0; i < pt_num; i++) {
		seal::Plaintext tmp(poly_length);
		for (int j = 0; j < poly_length; j++) {
			*(tmp.data() + j) = result[i][j];
		}
		ptv.push_back(tmp);
	}
	return ptv;
}

void ptv_to_lwe_ctv(std::vector<seal::Plaintext> ptv, std::vector<LWECT> lwe_ctv) {
	// Read the data from ptv to vector
	std::vector<std::vector<uint64_t>> ptv_data = std::vector(ptv.size(), std::vector<uint64_t>(ptv[0].coeff_count()));
	for (int i = 0; i < ptv.size(); i++) {
		for (int j = 0; j < ptv[0].coeff_count(); j++) {
			ptv_data[i][j] = *(ptv[i].data() + j);
		}
	}
	// Compose ptv_data according to the rule which we decompose a 60 bits number to 3 20 bits number
	std::size_t lwe_ct_num = lwe_ctv.size();
	std::vector<std::vector<uint64_t>> lwe_ctv_data = std::vector(lwe_ct_num, std::vector<uint64_t>(3 * (1 + ptv[0].coeff_count())));
	std::size_t num = ptv[0].coeff_count() / lwe_ct_num; // The number of column in each plaintext
	for (int i = 0; i < lwe_ct_num; i++) {
		for (int j = 0; j < 3 * (1 + ptv[0].coeff_count()); j++) {
			std::size_t total_index = j * lwe_ct_num + i;
			std::size_t num_per_pt = (ptv[0].coeff_count() / lwe_ct_num) * lwe_ct_num;
			std::size_t pt_index = total_index / num_per_pt;
			std::size_t index = total_index - pt_index * num_per_pt;
			lwe_ctv_data[i][j] = ptv_data[pt_index][index];
		}
	}
	// Transform lwe_ctv_data to vector of lwe_ct
	for (int i = 0; i < lwe_ct_num; i++) {
		lwe_ctv[i].set_ct0((lwe_ctv_data[i][2] >> 40) + (lwe_ctv_data[i][1] >> 20) + lwe_ctv_data[i][0]);
		seal::Plaintext tmp(ptv[0].coeff_count());
		for (int j = 0; j < ptv[0].coeff_count(); j++) {
			*(tmp.data() + j) = lwe_ctv_data[i][3 * (j + 1)] + (lwe_ctv_data[i][3 * (j + 1) + 1] >> 20) + (lwe_ctv_data[i][3 * (j + 1) + 2] >> 40);
		}
		lwe_ctv[i].set_ct1(tmp);
	}
}