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

#ifndef _IPPCRYPTO_COMMON_H
#define _IPPCRYPTO_COMMON_H

#include <strings.h>
#include <ctype.h>

#include <openssl/rand.h>

/* Useful defines */

#define IPPCP_DATA_ALIGNMENT  ((int)sizeof(void *))
static Ipp64s IPP_INT_PTR( const void* ptr )
{
    union {
        void*   Ptr;
        Ipp64s  Int;
    } dd;
    dd.Ptr = (void*)ptr;
    return dd.Int;
}
#define IPP_ALIGN_TYPE(type, align)      ((align)/sizeof(type)-1)
#define IPP_BYTES_TO_ALIGN(ptr, align)   ((~(IPP_INT_PTR(ptr)&((align)-1))+1)&((align)-1))
#define IPP_ALIGNED_PTR(ptr, align)      (void*)( (unsigned char*)(ptr) + (IPP_BYTES_TO_ALIGN( ptr, align )) )

#define IPPCP_BYTES2BITS(BITSIZE)   ((BITSIZE) * 8)
#define IPPCP_BITS2BYTES(BYTESIZE)  (((BYTESIZE) + 7) >> 3)

__attribute__((aligned(64))) static const Ipp8u seed0[]  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00";

/* Useful stuff functions */

// Inverts order of the data to fit the expected by API data representation
static void dataReverse(Ipp8u* pBuf, const char* str, int size) {
    for(int i = 0; i < size; i++) {
        pBuf[i] = str[size - i - 1];
    }
}

// A helper function to set IppsBigNumState context
static IppStatus ippcp_init_set_bn(IppsBigNumState *pbn, int max_word_len, IppsBigNumSGN sgn,
                                   const Ipp32u *pdata, int data_word_len) {
    IppStatus sts;
    sts = ippsBigNumInit(max_word_len, pbn);
    if (sts != ippStsNoErr)
        return sts;

    sts = ippsSet_BN(sgn, data_word_len, pdata, pbn);
    return sts;
}

// A helper function to allocate IppsBigNumState context
static IppsBigNumState* newBN(int numberWordSize, const Ipp32u* pData) {
    int bnByteSize;
    IppStatus sts = ippsBigNumGetSize(numberWordSize, &bnByteSize);
    if (sts != ippStsNoErr) {
        return NULL;
    }

    BUFFER_INIT(buff)
    alloc_buf(bnByteSize+8, &buff);
    IppsBigNumState* BN = (IppsBigNumState *)buff.buf;
    sts = ippcp_init_set_bn(BN, numberWordSize,  ippBigNumPOS, pData,  numberWordSize);
    if (sts != ippStsNoErr) {
	    free_buf(&buff);
        return NULL;
    }

    return BN;
}

// A helper function to generate random string
static Ipp32u* rand32(Ipp32u* pX, int size) {
   for (int n = 0; n < size; n++)
      pX[n] = (rand() << 16) + rand();
   return pX;
}

// A helper function to init new PRNG
static IppsPRNGState* newPRNG(void)
{
    int ctxSize = 0;
    IppsPRNGState* pRand = 0;
    ippsPRNGGetSize(&ctxSize);
    pRand = (IppsPRNGState*)(malloc(ctxSize));

    int seedBitSize = 200;
    int seedWordSize = 6;
    Ipp32u dataSeed[25];
    IppsBigNumState* seed = newBN(seedWordSize, rand32(dataSeed, IPPCP_BITS2BYTES(seedBitSize)));

    IppStatus sts = ippsPRNGInit(seedBitSize, pRand);
    if (sts != ippStsNoErr) {
	    free_buf((struct buffer*)seed);
        return NULL;
    }
    //sts = ippsPRNGSetSeed(seed, pRand);
    if (sts != ippStsNoErr) {
        free_buf((struct buffer*)seed);
        return NULL;
    }

    return pRand;
}


#endif //_IPPCRYPTO_COMMON_H
