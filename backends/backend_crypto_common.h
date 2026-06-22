/*************************************************************************
* Copyright (C) 2024 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

#ifndef _BACKEND_CRYPTO_COMMON_H
#define _BACKEND_CRYPTO_COMMON_H

#ifdef DETERMINISTIC_KEY_GEN
#include <pthread.h>

#ifndef OPENSSL_IS_BORINGSSL
static int stdlib_rand_seed(const void* buf, int num)
{
    (void)num;
    srand(*((unsigned int*)buf));
    return 1;
}

static int stdlib_rand_bytes(unsigned char* buf, int num)
{
    for (int index = 0; index < num; ++index) {
        buf[index] = rand() % 256;
    }
    return 1;
}
#else
static void stdlib_rand_seed(const void* buf, int num) { (void)num; srand(*((unsigned int*)buf)); }

static int stdlib_rand_bytes(uint8_t* buf, size_t num)
{
    for (int index = 0; index < num; ++index) {
        buf[index] = rand() % 256;
    }
    return 1;
}
#endif

// Suppress deprecation warnings for RAND_METHOD usage in OpenSSL 3.x
#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

RAND_METHOD stdlib_rand_meth = {
    stdlib_rand_seed, stdlib_rand_bytes, NULL, NULL, stdlib_rand_bytes, NULL
};
#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic pop
#endif

// Thread-safe global state
static int global_key_counter = 0;
static pthread_mutex_t rng_mutex = PTHREAD_MUTEX_INITIALIZER;
static const RAND_METHOD* original_rng_method = NULL;

static void set_drng_to_gen_rep_seq_protected(Ipp32u base_seed, int inc_seed)
{
    // Lock mutex to protect both counter and RNG state
    pthread_mutex_lock(&rng_mutex);

    int seed = base_seed;
    if (inc_seed) {
        // Get unique seed for this thread/call
        seed = base_seed + global_key_counter++;
    }

    // Suppress deprecation warnings for OpenSSL 3.x
#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    // Store original RNG method for restoration (only once)
    if (!original_rng_method) {
        original_rng_method = RAND_get_rand_method();
    }

    // Set deterministic RNG for generation
    RAND_set_rand_method(&stdlib_rand_meth);
    RAND_seed(&seed, sizeof(Ipp32u));

#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic pop
#endif
    // DON'T unlock here - keep RNG locked during key generation
}

static void restore_original_rng_protected()
{
#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    // Restore original RNG method
    if (original_rng_method) {
        RAND_set_rand_method(original_rng_method);
        // Don't reset original_rng_method to NULL - we might need it again
    }
#if OPENSSL_VERSION_MAJOR >= 3
#pragma GCC diagnostic pop
#endif
    // Unlock mutex after key generation is complete
    pthread_mutex_unlock(&rng_mutex);
}
#endif

#endif //_BACKEND_CRYPTO_COMMON_H
