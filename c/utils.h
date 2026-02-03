/*
utils.h

Defines basic utility functions.
*/

#ifndef CKB_UTILS_H_
#define CKB_UTILS_H_

/* a and b are since value,
 return 0 if a is equals to b,
 return -1 if a is less than b,
 return 1 if a is greater than b */
int epoch_number_with_fraction_cmp(uint64_t a, uint64_t b) {
  static const size_t NUMBER_OFFSET = 0;
  static const size_t NUMBER_BITS = 24;
  static const uint64_t NUMBER_MAXIMUM_VALUE = (1 << NUMBER_BITS);
  static const uint64_t NUMBER_MASK = (NUMBER_MAXIMUM_VALUE - 1);
  static const size_t INDEX_OFFSET = NUMBER_BITS;
  static const size_t INDEX_BITS = 16;
  static const uint64_t INDEX_MAXIMUM_VALUE = (1 << INDEX_BITS);
  static const uint64_t INDEX_MASK = (INDEX_MAXIMUM_VALUE - 1);
  static const size_t LENGTH_OFFSET = NUMBER_BITS + INDEX_BITS;
  static const size_t LENGTH_BITS = 16;
  static const uint64_t LENGTH_MAXIMUM_VALUE = (1 << LENGTH_BITS);
  static const uint64_t LENGTH_MASK = (LENGTH_MAXIMUM_VALUE - 1);

  /* extract a epoch */
  uint64_t a_epoch = (a >> NUMBER_OFFSET) & NUMBER_MASK;
  uint64_t a_index = (a >> INDEX_OFFSET) & INDEX_MASK;
  uint64_t a_len = (a >> LENGTH_OFFSET) & LENGTH_MASK;

  /* extract b epoch */
  uint64_t b_epoch = (b >> NUMBER_OFFSET) & NUMBER_MASK;
  uint64_t b_index = (b >> INDEX_OFFSET) & INDEX_MASK;
  uint64_t b_len = (b >> LENGTH_OFFSET) & LENGTH_MASK;

  if (a_epoch < b_epoch) {
    return -1;
  } else if (a_epoch > b_epoch) {
    return 1;
  } else {
    /* a and b is in the same epoch,
       compare a_index / a_len <=> b_index / b_len
     */
    uint64_t a_block = a_index * b_len;
    uint64_t b_block = b_index * a_len;
    /* compare block */
    if (a_block < b_block) {
      return -1;
    } else if (a_block > b_block) {
      return 1;
    } else {
      return 0;
    }
  }
}

/* Hex decoding utilities for delegate lock argv parsing.
   When a lock script runs under delegate lock, args are passed via ckb_exec
   as a hex-encoded string in argv[0]. */
int hex_to_nibble(char c) {
  if ((unsigned)(c - '0') < 10) {
    return c - '0';
  } else if ((unsigned)(c - 'A') < 6) {
    return c - 'A' + 10;
  } else if ((unsigned)(c - 'a') < 6) {
    return c - 'a' + 10;
  } else {
    return -1;
  }
}

/* Decode hex string to bytes with fixed output length.
   Returns 0 on success, -1 on error (wrong length or invalid hex). */
int decode_hex(const char *hex, unsigned char *out, size_t out_len) {
  size_t i = 0;
  for (; i < out_len; i++) {
    int hi = hex_to_nibble(hex[i << 1]);
    int lo = hex_to_nibble(hex[i << 1 | 1]);
    if ((hi | lo) < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  /* Ensure hex string is exactly 2*out_len characters (null-terminated) */
  if (hex[i << 1] != '\0') {
    return -1;
  }
  return 0;
}

/* Decode hex string to bytes with variable output length.
   Returns decoded byte length on success, -1 on error. */
int decode_hex_var(const char *hex, unsigned char *out, size_t max_len) {
  size_t i = 0;
  while (hex[i << 1] != '\0' && i < max_len) {
    int hi = hex_to_nibble(hex[i << 1]);
    if (hi < 0) {
      return -1;
    }
    int lo = hex_to_nibble(hex[i << 1 | 1]);
    if (lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
    i++;
  }
  /* Check for truncation or odd-length hex */
  if (hex[i << 1] != '\0') {
    return -1;
  }
  return (int)i;
}

#endif /* CKB_UTILS_H_ */
