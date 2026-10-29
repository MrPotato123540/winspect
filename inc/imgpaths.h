#ifndef WINSPECT_IMGPATHS_H
#define WINSPECT_IMGPATHS_H

// Where the evidence lives in an offline Windows installation (a mounted
// image or a copy that keeps the folder layout). Shared by `image` and
// `timeline --root`. Every path is checked; a missing one is left empty.

#include <windows.h>

#define IMG_MAX_USERS 64
#define IMG_MAX_LOGS  6

typedef struct {
    char name[128];
    char ntuser[MAX_PATH * 2];      // always present (it is how a profile is recognised)
    char usrclass[MAX_PATH * 2];    // AppData\Local\Microsoft\Windows\UsrClass.dat
    char pshist[MAX_PATH * 2];      // PSReadLine ConsoleHost_history.txt
    char recent[MAX_PATH * 2];      // AppData\Roaming\Microsoft\Windows\Recent (.lnk)
    char autodest[MAX_PATH * 2];    // Recent\AutomaticDestinations (Jump Lists)
} img_user;

typedef struct {
    char root[MAX_PATH];
    char system[MAX_PATH * 2], software[MAX_PATH * 2], sam[MAX_PATH * 2], amcache[MAX_PATH * 2];
    char prefetch[MAX_PATH * 2], tasks[MAX_PATH * 2], recycle[MAX_PATH * 2];
    char evtx[IMG_MAX_LOGS][MAX_PATH * 2];
    int nevtx;
    img_user users[IMG_MAX_USERS];
    int nusers;
} img_paths;

// Fills p from root. Returns 0, or -1 when neither SYSTEM nor SOFTWARE exists
// (not a Windows installation).
int img_find(const char *root, img_paths *p);

#endif
