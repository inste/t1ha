/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>





#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

#define HASH_JEN(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)_hj_key[10] << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)_hj_key[9] << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += _hj_key[4];                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += _hj_key[0];                                                \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)


uint64_t hash_jen_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_JEN(key, keylen, retval);
	return retval;
}

#define HASH_OAT(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _ho_i;                                                                \
  const unsigned char *_ho_key=(const unsigned char*)(key);                      \
  hashv = 0;                                                                     \
  for(_ho_i=0; _ho_i < keylen; _ho_i++) {                                        \
      hashv += _ho_key[_ho_i];                                                   \
      hashv += (hashv << 10);                                                    \
      hashv ^= (hashv >> 6);                                                     \
  }                                                                              \
  hashv += (hashv << 3);                                                         \
  hashv ^= (hashv >> 11);                                                        \
  hashv += (hashv << 15);                                                        \
} while (0)


uint64_t hash_oat_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_OAT(key, keylen, retval);
	return retval;
}

#define HASH_SAX(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _sx_i;                                                                \
  const unsigned char *_hs_key = (const unsigned char*)(key);                    \
  hashv = 0;                                                                     \
  for (_sx_i=0; _sx_i < keylen; _sx_i++) {                                       \
    hashv ^= (hashv << 5) + (hashv >> 2) + _hs_key[_sx_i];                       \
  }                                                                              \
} while (0)
/* FNV-1a variation */
#define HASH_FNV(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _fn_i;                                                                \
  const unsigned char *_hf_key = (const unsigned char*)(key);                    \
  (hashv) = 2166136261U;                                                         \
  for (_fn_i=0; _fn_i < keylen; _fn_i++) {                                       \
    hashv = hashv ^ _hf_key[_fn_i];                                              \
    hashv = hashv * 16777619U;                                                   \
  }                                                                              \
} while (0)


uint64_t hash_sax_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_SAX(key, keylen, retval);
	return retval;
}

uint64_t hash_fnv_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_FNV(key, keylen, retval);
	return retval;
}

#define HASH_BER(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hb_keylen = (unsigned)keylen;                                        \
  const unsigned char *_hb_key = (const unsigned char*)(key);                    \
  (hashv) = 0;                                                                   \
  while (_hb_keylen-- != 0U) {                                                   \
    (hashv) = (((hashv) << 5) + (hashv)) + *_hb_key++;                           \
  }                                                                              \
} while (0)

uint64_t hash_ber_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_BER(key, keylen, retval);
	return retval;
}


/* The Paul Hsieh hash function */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__)             \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)             \
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif
#define HASH_SFH(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned const char *_sfh_key=(unsigned const char*)(key);                     \
  uint32_t _sfh_tmp, _sfh_len = (uint32_t)keylen;                                \
                                                                                 \
  unsigned _sfh_rem = _sfh_len & 3U;                                             \
  _sfh_len >>= 2;                                                                \
  hashv = 0xcafebabeu;                                                           \
                                                                                 \
  /* Main loop */                                                                \
  for (;_sfh_len > 0U; _sfh_len--) {                                             \
    hashv    += get16bits (_sfh_key);                                            \
    _sfh_tmp  = ((uint32_t)(get16bits (_sfh_key+2)) << 11) ^ hashv;              \
    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \
    _sfh_key += 2U*sizeof (uint16_t);                                            \
    hashv    += hashv >> 11;                                                     \
  }                                                                              \
                                                                                 \
  /* Handle end cases */                                                         \
  switch (_sfh_rem) {                                                            \
    case 3: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 16;                                                \
            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)]) << 18;              \
            hashv += hashv >> 11;                                                \
            break;                                                               \
    case 2: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 11;                                                \
            hashv += hashv >> 17;                                                \
            break;                                                               \
    case 1: hashv += *_sfh_key;                                                  \
            hashv ^= hashv << 10;                                                \
            hashv += hashv >> 1;                                                 \
  }                                                                              \
                                                                                 \
  /* Force "avalanching" of final 127 bits */                                    \
  hashv ^= hashv << 3;                                                           \
  hashv += hashv >> 5;                                                           \
  hashv ^= hashv << 4;                                                           \
  hashv += hashv >> 17;                                                          \
  hashv ^= hashv << 25;                                                          \
  hashv += hashv >> 6;                                                           \
} while (0)


uint64_t hash_sfh_(const void * key, size_t keylen, uint64_t seed)
{
	uint64_t retval = seed;
	HASH_SFH(key, keylen, retval);
	return retval;
}





double bench_mats(void) { return mera_bench(NULL, NULL, 0, 0); }

void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed) {

  printf("%-24s: ", caption);
  fflush(NULL);

  double value = mera_bench(hash, data, len, seed);
  printf("%10.3f %s/hash, %6.3f %s/byte, %6.3f byte/%s", value, mera.units,
         value / len, mera.units, len / value, mera.units);

  if (mera.flags & timestamp_cycles) {
    printf(", %6.3f Gb/s @3GHz", 3.0 * len / value);
  } else if ((mera.flags & timestamp_ticks) == 0) {
    printf(", %6.3f Gb/s", len / value);
  }
  printf(" %s\n", (mera.flags & timestamp_clock_stable) ? "" : "roughly");

  if (is_option_set(bench_verbose)) {
    printf(" - convergence: ");
    if (mera_bci.retry_count)
      printf("retries %u, ", mera_bci.retry_count);
    printf("restarts %u, accounted-loops %u, worthless-loops %u, spent <%us\n",
           mera_bci.restart_count, mera_bci.target_accounted_loops,
           mera_bci.target_worthless_loops, mera_bci.spent_seconds);
    printf(" - mats/overhead: best %" PRIu64 ", gate %" PRIu64
           ", inner-loops-max %u, best-count %u\n",
           mera_bci.overhead_best, mera_bci.overhead_gate,
           mera_bci.overhead_loops_max, mera_bci.overhead_best_count);
    printf(" - hash: loops %u, best %" PRIu64 ", gate %" PRIu64
           ", tailloops-max %u, best-count %u\n\n",
           mera_bci.target_loops, mera_bci.target_best, mera_bci.target_gate,
           mera_bci.tail_loops_max, mera_bci.target_best_count);
  }
  fflush(NULL);
}

uint64_t thunk_XXH32(const void *input, size_t length, uint64_t seed) {
  return XXH32(input, length, (uint32_t)seed);
}

uint64_t thunk_HighwayHash64_pure_c(const void *input, size_t length,
                                    uint64_t seed) {
  uint64_t key[4] = {seed, seed, seed, seed};
  return HighwayHash64_pure_c(key, input, length);
}

void bench_size(const unsigned size, const char *caption) {
  printf("\nBench for %s keys (%u bytes):\n", caption, size);
  const uint64_t seed = 42;
  char *buffer = malloc(size);
  for (unsigned i = 0; i < size; ++i)
    buffer[i] = (char)(rand() + i);

#ifndef T1HA2_DISABLED
  if (is_selected(bench_64 | bench_2)) {
    bench("t1ha2_atonce", t1ha2_atonce, buffer, size, seed);
    bench("t1ha2_atonce128*", thunk_t1ha2_atonce128, buffer, size, seed);
    bench("t1ha2_stream*", thunk_t1ha2_stream, buffer, size, seed);
    bench("t1ha2_stream128*", thunk_t1ha2_stream128, buffer, size, seed);
  }
#endif

#ifndef T1HA1_DISABLED
  if (is_selected(bench_64 | bench_le | bench_1))
    bench("t1ha1_64le", t1ha1_le, buffer, size, seed);
  if (is_selected(bench_64 | bench_be | bench_1))
    bench("t1ha1_64be", t1ha1_be, buffer, size, seed);
#endif

#ifndef T1HA0_DISABLED
  if (is_selected(bench_0))
    bench("t1ha0", t1ha0, buffer, size, seed);
  if (is_selected(bench_32 | bench_le | bench_0))
    bench("t1ha0_32le", t1ha0_32le, buffer, size, seed);
  if (is_selected(bench_32 | bench_be | bench_0))
    bench("t1ha0_32be", t1ha0_32be, buffer, size, seed);

#if T1HA0_AESNI_AVAILABLE
  if (is_selected(bench_aes)) {
    bench("t1ha0_ia32aes_noavx_a", t1ha0_ia32aes_noavx_a, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx_b", t1ha0_ia32aes_noavx_b, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, buffer, size, seed);
    if (is_selected(bench_avx)) {
      bench("t1ha0_ia32aes_avx_a", t1ha0_ia32aes_avx_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx_b", t1ha0_ia32aes_avx_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, buffer, size, seed);
    }
#ifndef __e2k__
    if (is_selected(bench_avx2)) {
      bench("t1ha0_ia32aes_avx2_a", t1ha0_ia32aes_avx2_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2_b", t1ha0_ia32aes_avx2_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, buffer, size, seed);
    }
#endif /* !__e2k__ */
  }
#endif /* T1HA0_AESNI_AVAILABLE */
#endif /* T1HA0_DISABLED */

  if (is_selected(bench_xxhash)) {
    bench("xxhash32", thunk_XXH32, buffer, size, seed);
    bench("xxhash64", XXH64, buffer, size, (uint32_t)seed);
  }
  
  
  bench("HASH_JEN", hash_jen_, buffer, size, seed);
  bench("HASH_OAT", hash_oat_, buffer, size, seed);
  bench("HASH_SAX", hash_sax_, buffer, size, seed);
  bench("HASH_FNV", hash_fnv_, buffer, size, seed);
  bench("HASH_BER", hash_ber_, buffer, size, seed);
  bench("HASH_SFH", hash_sfh_, buffer, size, seed);
  
  if (is_selected(bench_highwayhash)) {
    bench("HighwayHash64_pure_c", thunk_HighwayHash64_pure_c, buffer, size,
          seed);
    bench("HighwayHash64_portable", thunk_HighwayHash64_Portable, buffer, size,
          seed);
#ifdef __ia32__
    if (ia32_cpu_features.basic.ecx & (1ul << 19))
      bench("HighwayHash64_sse41", thunk_HighwayHash64_SSE41, buffer, size,
            seed);
    if (ia32_cpu_features.extended_7.ebx & 32)
      bench("HighwayHash64_avx2", thunk_HighwayHash64_AVX2, buffer, size, seed);
#endif
#ifdef __e2k__
    bench("HighwayHash64_sse41", thunk_HighwayHash64_SSE41, buffer, size, seed);
#endif
    /* TODO: thunk_HighwayHash64_VSX() */
  }
  free(buffer);
}
