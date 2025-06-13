#ifndef FILE_H
#define FILE_H

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

int encrypt_file(File *file, const char *enckey, FILE *dst);
int decrypt_file(File *file, const char *enckey, FILE *dst);
int replace_by(File *file, const char *filename, const char *key);

#endif