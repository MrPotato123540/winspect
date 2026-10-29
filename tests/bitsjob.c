// bitsjob - TEST FIXTURE ONLY (CI / wine prefix): creates one suspended BITS
// download job with a notify command line so `winspect bits` has something to
// report, waits for a line on stdin, then cancels the job again. The job is
// never resumed, so nothing is downloaded and the command never runs.
// Build: x86_64-w64-mingw32-gcc -O2 tests/bitsjob.c -o bitsjob.exe -lole32 -lbits -luuid
#define COBJMACROS
#include <windows.h>
#include <bits.h>
#include <bits1_5.h>
#include <stdio.h>

int main(void)
{
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) return 1;
    IBackgroundCopyManager *m = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_BackgroundCopyManager, NULL, CLSCTX_LOCAL_SERVER,
                                  &IID_IBackgroundCopyManager, (void **)&m);
    if (FAILED(hr)) { printf("manager 0x%08lx\n", (unsigned long)hr); return 1; }
    GUID id;
    IBackgroundCopyJob *j = NULL;
    hr = IBackgroundCopyManager_CreateJob(m, L"winspect-test-job", BG_JOB_TYPE_DOWNLOAD, &id, &j);
    if (FAILED(hr)) { printf("create 0x%08lx\n", (unsigned long)hr); return 1; }
    hr = IBackgroundCopyJob_AddFile(j, L"http://10.0.0.5/payload.bin", L"C:\\winspect-bits-test.bin");
    printf("addfile 0x%08lx\n", (unsigned long)hr);
    IBackgroundCopyJob2 *j2 = NULL;
    if (SUCCEEDED(IBackgroundCopyJob_QueryInterface(j, &IID_IBackgroundCopyJob2, (void **)&j2))) {
        hr = IBackgroundCopyJob2_SetNotifyCmdLine(j2, L"C:\\Windows\\System32\\cmd.exe",
                                                  L"C:\\Windows\\System32\\cmd.exe /c echo test");
        printf("notify 0x%08lx\n", (unsigned long)hr);
        IBackgroundCopyJob2_Release(j2);
    }
    printf("ready\n");
    fflush(stdout);
    char line[16];
    fgets(line, sizeof line, stdin);
    IBackgroundCopyJob_Cancel(j);
    IBackgroundCopyJob_Release(j);
    IBackgroundCopyManager_Release(m);
    CoUninitialize();
    return 0;
}
