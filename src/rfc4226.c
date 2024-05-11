#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "rfc4226.h"

uint8_t*
hmac(unsigned char* key, int kl, uint64_t interval) {

	return (uint8_t*)HMAC(EVP_sha1(), key, kl,
		(const unsigned char*)&interval, sizeof(interval), NULL, 0);

}

uint32_t
DT(uint8_t* rawData) {

	uint64_t offset;
	uint32_t bin_code;


	/*
	* Truncate to 32-bit binary sequence.
	*/
	offset = rawData[19] & 0xf;

	bin_code = (rawData[offset] & 0x7f) << 24
		| (rawData[offset + 1] & 0xff) << 16
		| (rawData[offset + 2] & 0xff) << 8
		| (rawData[offset + 3] & 0xff);


	return bin_code;
}

uint32_t
mod_hotp(uint32_t bin_code, int digits) {

	int power = pow(10, digits);

	uint32_t otp = bin_code % power;

	return otp;

}

int
machine_endianness_type() {

	unsigned short int a = 1;
	char ist_byte = *((char*)&a);
	if (ist_byte == 0)
		return 0;
	else if (ist_byte == 1)
		return 1;
}

uint32_t
HOTP(uint8_t* key, size_t kl, uint64_t interval, int digits) {

	uint8_t* rawData;
	uint32_t result;
	uint32_t endianness;

	/*
	* Converting the interval from little endian
	* to big endian, if required
	*/
	if (machine_endianness_type()) {

		interval = ((interval & 0x00000000ffffffff) << 32) | ((interval & 0xffffffff00000000) >> 32);
		interval = ((interval & 0x0000ffff0000ffff) << 16) | ((interval & 0xffff0000ffff0000) >> 16);
		interval = ((interval & 0x00ff00ff00ff00ff) << 8) | ((interval & 0xff00ff00ff00ff00) >> 8);

	}

	//Step - 1, get the hashed integer value.
	rawData = (uint8_t*)hmac(key, kl, interval);

	//Step - 2, get dynamically truncated code.
	uint32_t truncData = DT(rawData);

	//Step - 3 calculate the final result by modding it.
	result = mod_hotp(truncData, digits);

	return result;
}

