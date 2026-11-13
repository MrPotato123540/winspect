cmake_minimum_required(VERSION 3.21)
 
project(winspect C RC)
 
add_executable(winspect
    src/main.c
    res/winspect.rc
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
    src/patchdec.c
    src/strings.c
    src/services.c
    src/drivers.c
    src/autoruns.c
    src/pipes.c
    src/hash.c
    src/hashlist.c
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
    src/regf.c
    src/regsrc.c
    src/hive.c
    src/amcache.c
    src/rdp.c
    src/sysinfo.c
    src/programs.c
    src/shellitem.c
    src/shellbags.c
    src/pshistory.c
    src/recyclebin.c
    src/bitsjobs.c
    src/comhijack.c
    src/users.c
    src/capture.c
    src/jsonmini.c
    src/evtx.c
    src/image.c
    src/imgpaths.c
    src/sqlite.c
    src/browser.c
    src/pca.c
    src/textfile.c
    src/setupapi.c
    src/evsrc.c
    src/logonparse.c
    src/logons.c
    src/bootparse.c
    src/boots.c
    src/dnscache.c
    src/werparse.c
    src/wer.c
    src/officeparse.c
    src/office.c
    src/magicparse.c
    src/magic.c
    src/defhist.c
    src/detections.c
    src/activities.c
    src/mft.c
    src/mftcmd.c
    src/usn.c
    src/usncmd.c
    src/esedb.c
    src/srum.c
    src/webcache.c
    src/timeline.c
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
target_link_libraries(winspect PRIVATE ntdll advapi32 psapi wintrust crypt32 dbghelp iphlpapi authz bcrypt wtsapi32 netapi32 shlwapi ole32 oleaut32 wbemuuid wevtapi shell32 bits dnsapi ws2_32 version)
 
# C11 makes anonymous unions standard, which winnt.h structs rely on
target_compile_features(winspect PRIVATE c_std_11)
 
# Faster builds, fewer macro collisions, we include extra headers explicitly
target_compile_definitions(winspect PRIVATE WIN32_LEAN_AND_MEAN)
 
if(MSVC)
	target_compile_options(winspect PRIVATE /W4)
	target_compile_definitions(winspect PRIVATE _CRT_SECURE_NO_WARNINGS)
	# res/winspect.rc embeds our own manifest (UTF-8 code page); the linker's
	# generated one would be a duplicate RT_MANIFEST resource.
	target_link_options(winspect PRIVATE /MANIFEST:NO)
else()
	target_compile_options(winspect PRIVATE -Wall -Wextra -Wpedantic)
endif()
 