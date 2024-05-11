#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __USE_POSIX199309 1
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include "rfc6238.h"


#define T0 0
#define DIGITS 6
#define VALIDITY 30
#define TIME 2


/*******************************Code Taken from elsewhere********************************/

char b32_decode_char(char c);
void b32_decode(char** dst, size_t* dstlen, const char* src, size_t srclen);

void b32_decode(char** dst, size_t* dstlen, const char* src, size_t srclen)
{
    size_t padlen = 0;   // Number of ='s in padding
    size_t lastlen = 0;  // Length of last quantum in characters

    *dst = NULL;
    *dstlen = 0;

    // Check padding
    for (size_t i = 1; i < srclen; i++)
    {
        if (src[srclen - i] == '=')
            padlen++;
        else
            break;
    }

    // Check source material
    for (size_t i = 0; i < srclen - padlen; i++)
    {
        if (b32_decode_char(src[i]) > 0x1F)
        {
            // ERROR: one or more characters cannot be decoded
            return;
        }
    }

    // Calculate the length of the last quantum in src
    lastlen = (srclen - padlen) % 8;

    // How many quantums do we have?
    size_t qmax = (srclen - padlen) / 8;

    if (lastlen > 0)
    {
        // Last quantum is a partial quantum
        // ... qmax rounded down
        qmax += 1;
    }
    else
    {
        // Last quantum is a full quantum
        // ... length of last quantum is 8, not 0
        lastlen = 8;
    }

    // Calculate dst buffer size
    *dstlen = ((srclen - padlen) / 8) * 5;

    switch (lastlen)
    {
    case 8:
        break;
    case 7:
        *dstlen += 4;
        break;
    case 5:
        *dstlen += 3;
        break;
    case 4:
        *dstlen += 2;
        break;
    case 2:
        *dstlen += 1;
        break;
    default:
        // ERROR: Not a multiple of a byte.
        *dstlen = 0;
        break;
    }

    if (dstlen == 0)
    {
        // Either empty src, or an error occurred
        return;
    }

    // Allocate dst buffer
    *dst = (char*)malloc(sizeof(char) * (*dstlen));

    // Loop variables
    size_t qlen;
    char* pdst = *dst;
    const char* psrc = src;

    // Decode each quantum
    for (size_t q = 0; q < qmax; q++)
    {
        // Are we on the last quantum?
        if (q == qmax - 1)
            qlen = lastlen;
        else
            qlen = 8;

        // dst       0           1          2          3           4 
        //      [11111 111][11 11111 1][1111 1111][1 11111 11][111 11111]
        // src     0      1      2      3       4      5      6      7

        switch (qlen)
        {
            // 8 = 5 bytes in quantum
        case 8:
            pdst[4] = b32_decode_char(psrc[7]);
            pdst[4] |= b32_decode_char(psrc[6]) << 5;
            // 7 = 4 bytes in quantum
        case 7:
            pdst[3] = b32_decode_char(psrc[6]) >> 3;
            pdst[3] |= (b32_decode_char(psrc[5]) & 0x1F) << 2;
            pdst[3] |= b32_decode_char(psrc[4]) << 7;
            // 5 = 3 bytes in quantum
        case 5:
            pdst[2] = b32_decode_char(psrc[4]) >> 1;
            pdst[2] |= b32_decode_char(psrc[3]) << 4;
            // 4 = 2 bytes in quantum
        case 4:
            pdst[1] = b32_decode_char(psrc[3]) >> 4;
            pdst[1] |= (b32_decode_char(psrc[2]) & 0x1F) << 1;
            pdst[1] |= b32_decode_char(psrc[1]) << 6;
            // 2 = 1 byte in quantum
        case 2:
            pdst[0] = b32_decode_char(psrc[1]) >> 2;
            pdst[0] |= b32_decode_char(psrc[0]) << 3;
            break;
        default:
            break; // TODO error
        }

        // Move quantum pointers forward
        psrc += 8;
        pdst += 5;
    }
}

char b32_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    else if (c >= '2' && c <= '7')
        return c - '2' + 26;
    // ... handle lowercase here???
    else if (c >= 'a' && c <= 'z')
        return c - 'a';
    else
        return 0xFF; // ERROR 
}

/*******************************Code Taken from elsewhere********************************/

void
print_current_system_time() {
    time_t t;
    time(&t); /* Get the current time of the system */
    printf("%s ", ctime(&t));
}

void
timer_callback(union sigval arg) {

    char* decodeKey = (char*)arg.sival_ptr;

    size_t sz_dKey = strlen(decodeKey);

    time_t t = floor((time(NULL) - T0) / VALIDITY);

    uint32_t result = TOTP((uint8_t*)decodeKey, sz_dKey, (uint64_t)t, DIGITS);

    printf("The resulting OTP value is : %06u\n", result);

}

void
timer_demo(char* key) {

    int ret;
    timer_t timer;
    struct sigevent evp;

    memset(&timer, 0, sizeof(timer));

    /* evp variable is used to setup timer properties*/
    memset(&evp, 0, sizeof(struct sigevent));

    /* Fill the user defined data structure.
     * When timer expires, this will be passed as
     * argument to the timer callback handler */
    evp.sigev_value.sival_ptr = (void*)key;

    /* On timer Expiry, We want kernel to launch the
     * timer handler routine in a separate thread context */
    evp.sigev_notify = SIGEV_THREAD;

    /* Register the timer hander routine. This routine shall
     * be invoked when timer expires*/
    evp.sigev_notify_function = timer_callback;

    /* Create a timer. It is just a timer initialization, Timer
     * is not fired (Alarmed)  */
    ret = timer_create(CLOCK_REALTIME,
        &evp,
        &timer);

    if (ret < 0) {

        printf("Timer Creation failed, errno = %d\n", errno);
        exit(0);
    }

    /* Let us say, I want to start the timer after 5 seconds from now
     * (now =  say, t = 0) and once the 5 seconds elapsed, i
     * want the timer to keep firing after every 2 seconds repeatedly.
     * It simply mean that - if i start the timer as time t = 0, then
     * timer handler routine (timer_callback) shall be called at t = 5,
     * t = 7, t = 9 ... so on*/

     /* Let us setup the time intervals */

    struct itimerspec ts;

    /* I want the timer to fire for the first time after 5 seconds
     * and 0 nano seconds*/
    ts.it_value.tv_sec = 1;
    ts.it_value.tv_nsec = 0;

    /* After the timer has fired for the first time, i want the timer
     * to repeatedly fire after every 2 sec and 0 nano sec */
    ts.it_interval.tv_sec = VALIDITY;
    ts.it_interval.tv_nsec = 0;

    /* Now start the timer*/
    ret = timer_settime(timer,
        0,
        &ts,
        NULL);

    if (ret < 0) {

        printf("Timer Start failed, errno = %d\n", errno);
        exit(0);
    }
    else {
        print_current_system_time();
        printf("Timer Alarmed Successfully\n");
    }
}


int main(int argc, char* argv[]) {


    char key[50];
    char* k;
    char* decodeKey;
    size_t sz_dKey;
    uint32_t result;

    if (argc <= 1) {
        printf("Please provide your secret key!!!!!\n");
        return 0;
    }

    unsigned int sz_key = strlen(argv[1]);

    if (sz_key > 50) {
        printf("base-32 secret key cannot be more than 50 characters.\n");
        return 0;
    }


    //validate the key...
    for (int i = 0; i < sz_key; i++) {

        if ((argv[1][i] < 'A' && argv[1][i] > 'Z') ||
            (argv[1][i] < '2' && argv[1][i] > '9') ||
            (argv[1][i] == '=')) {

            printf("Invalid base-32 encoded key.\nPlease enter correct base-32 encoded key.\n");
            return 0;
        }
    }


    strncpy(key, argv[1], sz_key);


    k = key;

    b32_decode(&decodeKey, &sz_dKey, k, (size_t)sz_key);

    timer_demo(decodeKey);

    pause();

    return 0;
}