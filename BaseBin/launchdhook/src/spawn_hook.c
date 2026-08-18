#include <spawn.h>
#include <errno.h>
#include "../systemhook/src/common/common.h"
#include "boomerang.h"
#include "spawn_hook.h"
#include "crashreporter.h"
#include "roothide_trace.h"
#include "update.h"
#include <libjailbreak/util.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <litehook.h>
#include "jbserver/jbserver_local.h"
#include "hookd_provider.h"
extern char **environ;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);

#define LOG_PROCESS_LAUNCHES 0

extern bool gInEarlyBoot;
extern bool gFreeBootLogoBeforeBackboardd;
void free_boot_logo(void);

static int gSpawnHookInstallResult = KERN_FAILURE;
static bool gSpawnHookObservedBoomerang = false;
static volatile int gPostUserspaceRebootSpawnTraceRemaining = 0;
static volatile int gPostUserspaceRebootSpawnTraceSequence = 0;

int spawn_hook_install_result(void)
{
	return gSpawnHookInstallResult;
}

bool spawn_hook_observed_boomerang(void)
{
	return gSpawnHookObservedBoomerang;
}

void spawn_hook_note_userspace_reboot(void)
{
	gPostUserspaceRebootSpawnTraceSequence = 0;
	gPostUserspaceRebootSpawnTraceRemaining = 12;
}

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

void ensure_fakelib_mounted(void)
{
	struct statfs fsb;
	if (statfs("/usr/lib", &fsb) != 0) return;
	if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
		systemwide_domain_set_enabled(true);

		// The jailbreak server is not reachable at this point in the launchd lifecycle
		// So we need to host our own, just so that jbctl can talk to it
		mach_port_t serverPort = jbserver_local_start();
		jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
		jbserver_local_stop();

		// Note down that the jailbreak was hidden
		// So that after the userspace reboot, we can unmount fakelib again
		setenv("DOPAMINE_IS_HIDDEN", "1", true);
	}
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	int key = crashreporter_pause();
	int r = __posix_spawn_inline(pid, path, desc, argv, envp);
	crashreporter_resume(key);

	return r;
}

static short spawn_flags(struct _posix_spawn_args_desc *desc)
{
	short flags = 0;
	if (desc && desc->attrp) {
		posix_spawnattr_t attr = desc->attrp;
		if (posix_spawnattr_getflags(&attr, &flags) != 0) flags = 0;
	}
	return flags;
}

static const char *launchd_self_spawn_match(const char *path,
                                             struct _posix_spawn_args_desc *desc,
                                             char executablePath[PATH_MAX],
                                             short *flagsOut)
{
	if (flagsOut) *flagsOut = spawn_flags(desc);
	if (getpid() != 1 || !path) return NULL;

	uint32_t executablePathSize = PATH_MAX;
	executablePath[0] = '\0';
	if (_NSGetExecutablePath(executablePath, &executablePathSize) != 0) {
		executablePath[0] = '\0';
	}

	if (executablePath[0] && strcmp(path, executablePath) == 0) {
		return "exact-path";
	}

	if (executablePath[0]) {
		struct stat candidateStatus = {0};
		struct stat executableStatus = {0};
		if (stat(path, &candidateStatus) == 0 && stat(executablePath, &executableStatus) == 0 &&
		    candidateStatus.st_dev == executableStatus.st_dev && candidateStatus.st_ino == executableStatus.st_ino) {
			return "same-file";
		}
	}

	if (flagsOut && (*flagsOut & POSIX_SPAWN_SETEXEC)) {
		return "setexec";
	}

	return NULL;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (getpid() == 1 && gPostUserspaceRebootSpawnTraceRemaining > 0) {
		int sequence = ++gPostUserspaceRebootSpawnTraceSequence;
		gPostUserspaceRebootSpawnTraceRemaining--;
		roothide_trace("[launchd] post-RB2_USERREBOOT spawn observation #%d; path=%s flags=0x%x argv0=%s",
		               sequence, path ? path : "(null)", (unsigned short)spawn_flags(desc),
		               argv && argv[0] ? argv[0] : "(null)");
	}

	if (path) {
		char executablePath[PATH_MAX] = {0};
		short flags = 0;
		const char *matchReason = launchd_self_spawn_match(path, desc, executablePath, &flags);
		if (matchReason || (getpid() == 1 && string_has_suffix(path, "/launchd"))) {
			roothide_trace("[launchd] self-spawn candidate; path=%s self=%s flags=0x%x match=%s argv0=%s",
			               path, executablePath[0] ? executablePath : "(unavailable)", (unsigned short)flags,
			               matchReason ? matchReason : "none", argv && argv[0] ? argv[0] : "(null)");
		}

		if (matchReason) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn
			roothide_trace("[launchd] userspace-reboot self-spawn matched via %s; DYLD_INSERT_LIBRARIES=%s BOOMERANG_PID=%s",
			               matchReason, getenv("DYLD_INSERT_LIBRARIES") ?: "(unset)", getenv("BOOMERANG_PID") ?: "(unset)");

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

			// If the jailbreak is currently hidden, fakelib is not mounted
			// It needs to be mounted to regain launchd code execution after the userspace reboot
			ensure_fakelib_mounted();

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

			// Before the userspace reboot, we want to stash the primitives into boomerang
			int stashResult = boomerang_stashPrimitives();
			if (stashResult != 0) {
				roothide_trace("[boomerang] FAILURE: refusing userspace reboot because primitive stashing returned %d", stashResult);
				gInEarlyBoot = false;
				return EIO;
			}

			hookd_provider_teardown();

			// Fix Xcode debugging being broken after the userspace reboot
			unmount("/Developer", MNT_FORCE);

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				if (r != 0) {
					char msg[1000];
					snprintf(msg, 1000, "Failed updating basebin (error %d).", r);
					abort_with_reason(7, 1, msg, 0);
				}
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			int spawnResult = __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
			if (spawnResult != 0) {
				gInEarlyBoot = false;
				roothide_trace("[launchd] FAILURE: userspace-reboot self-spawn syscall returned %d", spawnResult);
			}
			return spawnResult;
		}
	}

#if LOG_PROCESS_LAUNCHES
	if (path) {
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "%s", path);
		int ai = 0;
		while (argv) {
			if (argv[ai]) {
				if (ai >= 1) {
					fprintf(f, " %s", argv[ai]);
				}
				ai++;
			}
			else {
				break;
			}
		}
		fprintf(f, "\n");
		fclose(f);

		// if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		// 	const char *tmpBlacklist[] = {
		// 		"com.apple.logd"
		// 	};
		// 	size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
		// 	for (size_t i = 0; i < blacklistCount; i++)
		// 	{
		// 		if (!strcmp(tmpBlacklist[i], firstArg)) {
		// 			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		// 			fprintf(f, "blocked injection %s\n", firstArg);
		// 			fclose(f);
		// 			return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
		// 		}
		// 	}
		// }
	}
#endif

	// The boomerang handoff child is spawned synchronously while launchd is
	// servicing the explicit reboot-preparation request.  It is already in the
	// BaseBin trust cache and must not recurse through normal child patching.
	if (path && string_has_suffix(path, "/basebin/boomerang")) {
		roothide_trace("[launchd] spawn hook observed boomerang handoff child; bypassing normal child patching");
		gSpawnHookObservedBoomerang = true;
		return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	}

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (path && !strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	// jailbreakd receives the launchd bootstrap port explicitly and must be
	// allowed to start before /usr/lib/systemhook.dylib exists.  Injecting the
	// normal systemwide hook here would leave it suspended on the first load.
	if (path && string_has_suffix(path, "/basebin/jailbreakd")) {
		return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	}

	// If we're drawing a boot logo, free up it's resources before backboardd starts
	if (gFreeBootLogoBeforeBackboardd) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			if (argv[0]) {
				if (argv[1]) {
					if (!strcmp(argv[1], "com.apple.backboardd\n")) {
						free_boot_logo();
						gFreeBootLogoBeforeBackboardd = false;
					}
				}
			}
		}
	}

	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}

void initSpawnHooks(void)
{
	gSpawnHookInstallResult = litehook_hook_function(__posix_spawn, __posix_spawn_hook);
	roothide_trace("[launchd] spawn hook installation returned %d; source=%p target=%p",
	               gSpawnHookInstallResult, (void *)__posix_spawn, (void *)__posix_spawn_hook);
}
