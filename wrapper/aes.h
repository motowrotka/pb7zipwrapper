#pragma once
#include <stdint.h>
#include <stddef.h>

void aes256_init(const uint8_t* key);
void aes256_encrypt_block(uint8_t* block);
void aes256_decrypt_block(uint8_t* block);

void aes256_cbc_encrypt(uint8_t* data, size_t len, const uint8_t* iv);
void aes256_cbc_decrypt(uint8_t* data, size_t len, const uint8_t* iv);
