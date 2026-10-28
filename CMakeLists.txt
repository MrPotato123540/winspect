cmake_minimum_required(VERSION 3.21)
 
project(winspect C)
 
add_executable(winspect
    src/main.c
    src/list.c
    src/pe.c
    src/inspect.c
    src/threads.c
    src/handles.c
    src/token.c
    src/secinfo.c
    src/ssn.c
    src/launch.c
    src/verify.c
    src/sign.c
    src/regions.c
    src/net.c
    src/triage.c
    src/detect.c
    src/strings.c
    src/services.c
    src/drivers.c
    src/autoruns.c
    src/pipes.c
    src/hash.c
    src/hosts.c
    src/certstore.c
    src/objects.c
    src/defender.c
    src/usb.c
    src/prefetch.c
    src/pfparse.c
    src/artparse.c
    src/shimcache.c
    src/bam.c
    src/firewall.c
    src/taskcache.c
    src/wmi.c
    src/capa.c
    src/lnkparse.c
    src/lnk.c
    src/hunt.c
    src/posture.c
    src/rights.c
    src/events.c
    src/hidden.c
    src/sweep.c
    src/streams.c
    src/usage.c
    src/userassist.c
    src/mru.c
    src/cfb.c
    src/destlist.c
    src/jumplist.c
    src/tasks.c
    src/modules.c
    src/arp.c
    src/sessions.c
    src/shares.c
    src/routes.c
    src/ioc.c
    src/entropy.c
    src/pecksum.c
    src/jsonutil.c
    src/md5.c
    src/imphash_ords.c
)

target_include_directories(winspect PRIVATE inc)

# inspect.c calls NtQueryInformationProcess, which lives in ntdll.
# MSVC resolves it through ntdll.lib / the Windows SDK; MinGW needs -lntdll.
target_link_libraries(winspect PRIVATE ntdll advapi32 psapi wintrust crypt32 dbghelp iphlpapi authz bcrypt wtsapi32 netapi32 shlwapi ole32 oleaut32 wbemuuid wevtapi shell32)
 
# C11 makes anonymous unions standard, which winnt.h structs rely on
target_compile_features(winspect PRIVATE c_std_11)
 
# Faster builds, fewer macro collisions, we include extra headers explicitly
target_compile_definitions(winspect PRIVATE WIN32_LEAN_AND_MEAN)
 
if(MSVC)
	target_compile_options(winspect PRIVATE /W4)
	target_compile_definitions(winspect PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
	target_compile_options(winspect PRIVATE -Wall -Wextra -Wpedantic)
endif()
 