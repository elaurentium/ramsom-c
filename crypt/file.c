/***************************************************************************************************
 * FILE:        file.c
 * PURPOSE:     Provides a basic abstraction for file encryption and decryption using AES-256-CTR.
 *
 * AUTHOR:      Evandro Lourenço Limeira
 * YEAR:        2025
 * GITHUB:      https://github.com/elaurentium
 *
 * DESCRIPTION:
 * This program encrypts or decrypts files using the OpenSSL library and AES-256 in CTR mode.
 * It supports processing large files in chunks and writing/reading IVs at the start of the file.
 *
 * USAGE:
 *     ./file <mode> <input file> <output file> <32-byte key>
 *
 *     - <mode>:         "encrypt" or "decrypt"
 *     - <input file>:   Path to the file to encrypt or decrypt
 *     - <output file>:  Path to the resulting output file
 *     - <32-byte key>:  Encryption key (must be exactly 32 bytes for AES-256)
 *
 * EXAMPLES:
 *     ./file encrypt input.txt encrypted.bin 12345678901234567890123456789012
 *     ./file decrypt encrypted.bin decrypted.txt 12345678901234567890123456789012
 *
 ***************************************************************************************************/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/stat.h>
 #include <openssl/aes.h>
 #include <openssl/rand.h>
 #include <openssl/evp.h>
 #include <openssl/ssl.h>
 #include <libgen.h>
 #include <unistd.h>
 
 #define AES_BLOCK_SIZE 16
 #define BUFFER_SIZE 4096
 
 typedef struct {
     char path[1024];
     char extension[16];
     struct stat file_info;
 } File;
 
 int encrypt_file(File *file, const char *enckey, FILE *dst) {
     FILE *inFile = fopen(file->path, "rb");
     if (!inFile) {
         perror("Error opening input file");
         return 1;
     }
 
     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     if (!ctx) {
         fprintf(stderr, "Error creating cipher context\n");
         fclose(inFile);
         return 1;
     }
 
     unsigned char iv[AES_BLOCK_SIZE];
     if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
         fprintf(stderr, "Error generating IV\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     // Write IV to the beginning of the destination file
     if (fwrite(iv, 1, AES_BLOCK_SIZE, dst) != AES_BLOCK_SIZE) {
         fprintf(stderr, "Error writing IV to output\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     // Initialize AES-256-CTR
     if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (unsigned char *)enckey, iv) != 1) {
         fprintf(stderr, "Error initializing encryption\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     unsigned char inbuf[BUFFER_SIZE];
     unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
     int inlen, outlen;
 
     while ((inlen = fread(inbuf, 1, BUFFER_SIZE, inFile)) > 0) {
         if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
             fprintf(stderr, "Error during encryption\n");
             EVP_CIPHER_CTX_free(ctx);
             fclose(inFile);
             return 1;
         }
         if (fwrite(outbuf, 1, outlen, dst) != outlen) {
             fprintf(stderr, "Error writing encrypted data\n");
             EVP_CIPHER_CTX_free(ctx);
             fclose(inFile);
             return 1;
         }
     }
 
     if (ferror(inFile)) {
         fprintf(stderr, "Error reading input file\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
         fprintf(stderr, "Error finalizing encryption\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     if (fwrite(outbuf, 1, outlen, dst) != outlen) {
         fprintf(stderr, "Error writing final encrypted data\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     EVP_CIPHER_CTX_free(ctx);
     fclose(inFile);
     return 0;
 }
 
 int decrypt_file(File *file, const char *enckey, FILE *dst) {
     FILE *inFile = fopen(file->path, "rb");
     if (!inFile) {
         perror("Error opening input file");
         return 1;
     }
 
     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     if (!ctx) {
         fprintf(stderr, "Error creating cipher context\n");
         fclose(inFile);
         return 1;
     }
 
     unsigned char iv[AES_BLOCK_SIZE];
     if (fread(iv, 1, AES_BLOCK_SIZE, inFile) != AES_BLOCK_SIZE) {
         fprintf(stderr, "Error reading IV\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     // Initialize AES-256-CTR
     if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (unsigned char *)enckey, iv) != 1) {
         fprintf(stderr, "Error initializing decryption\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     unsigned char inbuf[BUFFER_SIZE];
     unsigned char outbuf[BUFFER_SIZE];
     int inlen, outlen;
 
     while ((inlen = fread(inbuf, 1, BUFFER_SIZE, inFile)) > 0) {
         if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
             fprintf(stderr, "Error during decryption\n");
             EVP_CIPHER_CTX_free(ctx);
             fclose(inFile);
             return 1;
         }
         if (fwrite(outbuf, 1, outlen, dst) != outlen) {
             fprintf(stderr, "Error writing decrypted data\n");
             EVP_CIPHER_CTX_free(ctx);
             fclose(inFile);
             return 1;
         }
     }
 
     if (ferror(inFile)) {
         fprintf(stderr, "Error reading input file\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
         fprintf(stderr, "Error finalizing decryption\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     if (fwrite(outbuf, 1, outlen, dst) != outlen) {
         fprintf(stderr, "Error writing final decrypted data\n");
         EVP_CIPHER_CTX_free(ctx);
         fclose(inFile);
         return 1;
     }
 
     EVP_CIPHER_CTX_free(ctx);
     fclose(inFile);
     return 0;
 }
 
 int replace_by(File *file, const char *filename, const char *key) {
     FILE *dst = fopen(filename, "wb");
     if (!dst) {
         perror("Error opening destination file");
         return 1;
     }
 
     int ret = encrypt_file(file, key, dst);
     fclose(dst);
     return ret;
 }