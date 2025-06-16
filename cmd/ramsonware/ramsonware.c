#include "crypt.h"
#include "banner.h"

#define MAX_FILE_SIZE int64_t(20 + 1e+6)
#define TEMP_DIR "./tmp/"
#define ENCRYPTED_EXTENSION ".enc"
#define MAX_PATH 1024


typedef struct {
    File file;

} FileToRename;

void init() {
    banner();
}
