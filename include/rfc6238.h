#ifndef RFC6238_H
#define RFC6238_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>


#include "rfc4226.h"

#define TS 30 /* time step in seconds, default value */

uint32_t TOTP(uint8_t* key, size_t kl, uint64_t time, int digits);
time_t get_time(time_t T0);
#endif