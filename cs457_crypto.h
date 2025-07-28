#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>   
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h> 
#include<math.h>


// One-time pad encryption
char* one_time_pad_encr(const char* plain_text, size_t size, const char* key);
// One-time pad decryption 
char* one_time_pad_decr(const char* cipher_text, size_t size, const char* key);
// Function with examples 
void call_OTP(const char* plain_text, const char* key_str, size_t data_size);
// Generate random key
char* generate_key(size_t length);

// Affine Cipher encryption
char* affine_encr(const char* plain_text);
// Affine Cipher decryption
char* affine_decr(const char* cipher_text);
// Function with examples
void call_affine(const char* message);

// Substitution decryptor
void sub_decryptor(const char* cipher_text);

// Scytale encryption
char* scytale_encr(const char* plain_text, int rods);
// Scytale decryption
char* scytale_decr(const char* cipher_text, int rods);
// Restore orignal
char* restore_original(const char* decrypted_letters, const char* original_text);


#endif //CRYPTO_H