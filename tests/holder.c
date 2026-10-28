// Test helper for "handles": keeps a file with a known name open so that
// "handles --find <name>" has something to find. With a second argument
// "block" it also starts a synchronous read on an anonymous pipe that nobody
// writes to - the classic handle whose name query can hang a naive tool -
// so the test can check that handles still finishes. Exits after 60 s.
// Build: cc tests/holder.c -o holder.exe   (MinGW or MSVC)
#include <windows.h>

static DWORD WINAPI block_read(LPVOID p)
{
    char b;
    DWORD got;
    ReadFile((HANDLE)p, &b, 1, &got, NULL);     // never completes
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    HANDLE f = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 3;
    if (argc > 2 && lstrcmpiA(argv[2], "block") == 0) {
        HANDLE r, w;
        if (CreatePipe(&r, &w, NULL, 0)) {
            CreateThread(NULL, 0, block_read, r, 0, NULL);
        }
    }
    Sleep(60000);
    CloseHandle(f);
    return 0;
}
