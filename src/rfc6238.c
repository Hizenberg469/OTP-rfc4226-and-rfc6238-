#include "rfc6238.h"


time_t
get_time(time_t t0)
{
    return floor((time(NULL) - t0) / TS);
}

uint32_t
TOTP(uint8_t* key, size_t kl, uint64_t time, int digits)
{
    uint32_t totp;

    totp = HOTP(key, kl, time, digits);
    return totp;
}