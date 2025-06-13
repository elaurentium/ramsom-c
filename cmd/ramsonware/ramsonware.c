#include <includes/file.h>
#include <includes/banner.h>

void init() {
    banner();
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