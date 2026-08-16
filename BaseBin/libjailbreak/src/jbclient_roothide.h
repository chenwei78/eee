#ifndef JBCLIENT_ROOTHIDE_H
#define JBCLIENT_ROOTHIDE_H

#include <stdbool.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <xpc/xpc.h>

mach_port_t jbclient_jailbreakd_lookup(void);
mach_port_t jbclient_jailbreakd_checkin(void);
bool jbclient_roothide_jailbroken(void);
bool jbclient_palehide_present(void);
bool jbclient_blacklist_check_pid(pid_t pid);
bool jbclient_blacklist_check_path(const char *path);
bool jbclient_blacklist_check_bundle(const char *bundle);
int jbclient_trust_executable_recurse(const char *executablePath, xpc_object_t preferredArchsArray);
int jbclient_trust_library_recurse(const char *libraryPath, void *addressInCaller);
bool jbclient_dyld_patch_enabled(void);
int jbclient_set_dyld_patch(bool enabled);

#endif
