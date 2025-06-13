//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// !!                                                    provides a basic abstraction for file encryption/decryption                                                     !! //
// YEAR: 2025
// AUTHOR: EVANDRO LOURENÇO LIMEIRA
// GITHUB: https://github.com/elaurentium
//------------------------------------------------------------------------------------------------------------------------------------------------------------------------++++
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

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <mode> <input file> <output file> <32-byte key>\n", argv[0]);
        fprintf(stderr, "Mode: 'encrypt' or 'decrypt'\n");
        return 1;
    }

    const char *mode = argv[1];
    const char *input_path = argv[2];
    const char *output_path = argv[3];
    const char *key = argv[4];

    if (strlen(key) != 32) {
        fprintf(stderr, "Key must be exactly 32 bytes for AES-256\n");
        return 1;
    }

    // Initialize File structure
    File file;
    memset(&file, 0, sizeof(File));
    strncpy(file.path, input_path, sizeof(file.path) - 1);

    char *ext = strrchr(input_path, '.');
    if (ext && strlen(ext) < sizeof(file.extension)) {
        strncpy(file.extension, ext + 1, sizeof(file.extension) - 1);
    }

    if (stat(file.path, &file.file_info) != 0) {
        perror("Error getting file info");
        return 1;
    }

    FILE *outFile = fopen(output_path, "wb");
    if (!outFile) {
        perror("Error opening output file");
        return 1;
    }

    int result;
    if (strcmp(mode, "encrypt") == 0) {
        result = encrypt_file(&file, key, outFile);
        if (result == 0) {
            printf("Encryption successful.\n");
        } else {
            printf("Encryption failed.\n");
        }
    } else if (strcmp(mode, "decrypt") == 0) {
        result = decrypt_file(&file, key, outFile);
        if (result == 0) {
            printf("Decryption successful.\n");
        } else {
            printf("Decryption failed.\n");
        }
    } else {
        fprintf(stderr, "Invalid mode. Use 'encrypt' or 'decrypt'.\n");
        fclose(outFile);
        return 1;
    }

    fclose(outFile);
    return result;
}