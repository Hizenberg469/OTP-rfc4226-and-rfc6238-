#ifndef RFC4226_H
#define RFC4226_H


#include <stdint.h>
#include <stdlib.h>

/*
* Interface API for this library.
*/

uint32_t HOTP(uint8_t* key, size_t kl, uint64_t interval, int digits);

/*
* Step 1 -> Calling hmac function from openssl
*			library. It is used to create a 160-bit
*			integer value which is processed further.
*			It take a string key as an argument and
*			a seed value for calculation.
*			->unsigned char* key -> key string
*			->uint64_t interval -> seed value
*				|
*				|
*				-------> This seed value can be integer counter or
*						 timer value as an argument.
*/

uint8_t* hmac(unsigned char* key, int kl, uint64_t interval);


/*
*
* Step 2 -> This function will truncate some bits to produce
*			a binary sequence of 32-bit. The 160-bit binary
*			sequence should in big-endian binary format for
*			processing.
*/

uint32_t DT(uint8_t* rawData);
#endif