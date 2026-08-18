#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/jbclient_mach.h>
#import <libjailbreak/stock_fixes.h>
#import "internal.h"

#import <Foundation/Foundation.h>
#import <CoreServices/LSApplicationProxy.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)
extern char **environ;

static void RootHideJbctlTrace(const char *format, ...)
{
	const char *tracePath = getenv("ROOTHIDE_JBCTL_TRACE_PATH");
	if (!tracePath || !tracePath[0] || !format) return;

	int trace = open(tracePath, O_WRONLY | O_APPEND);
	if (trace < 0) return;

	struct stat traceStatus = {0};
	if (fstat(trace, &traceStatus) != 0 || traceStatus.st_size >= 256 * 1024) {
		close(trace);
		return;
	}

	char message[1024] = {0};
	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	dprintf(trace, "[jbctl] %s\n", message);
	fsync(trace);
	close(trace);
}

static int PerformUserspaceReboot(void)
{
	RootHideJbctlTrace("reboot_userspace entered; pid=%d ppid=%d uid=%d euid=%d gid=%d egid=%d",
	                   getpid(), getppid(), getuid(), geteuid(), getgid(), getegid());
	uint32_t csFlagsBefore = 0;
	errno = 0;
	int csopsBefore = csops(getpid(), CS_OPS_STATUS, &csFlagsBefore, sizeof(csFlagsBefore));
	int csopsBeforeErrno = errno;
	RootHideJbctlTrace("authorization before preflight; csops=%d errno=%d csflags=0x%08x platform=%d",
	                   csopsBefore, csopsBeforeErrno, csFlagsBefore,
	                   csopsBefore == 0 && (csFlagsBefore & CS_PLATFORM_BINARY) != 0);
	RootHideJbctlTrace("requesting launchd userspace-reboot preflight");
	int preparationResult = jbclient_prepare_userspace_reboot();
	RootHideJbctlTrace("launchd userspace-reboot preflight returned %d", preparationResult);
	if (preparationResult != 0) {
		RootHideJbctlTrace("FAILURE: refusing reboot because launchd preflight returned %d", preparationResult);
		return 70;
	}

	uint32_t csFlagsAfter = 0;
	errno = 0;
	int csopsAfter = csops(getpid(), CS_OPS_STATUS, &csFlagsAfter, sizeof(csFlagsAfter));
	int csopsAfterErrno = errno;
	bool isPlatformAfter = csopsAfter == 0 && (csFlagsAfter & CS_PLATFORM_BINARY) != 0;
	RootHideJbctlTrace("authorization after preflight; csops=%d errno=%d csflags=0x%08x platform=%d",
	                   csopsAfter, csopsAfterErrno, csFlagsAfter, isPlatformAfter);
	if (!isPlatformAfter) {
		RootHideJbctlTrace("FAILURE: refusing reboot because jbctl is not a platform process after preflight");
		return 71;
	}

	if (@available(iOS 18.0, *)) {
		// Use Apple's platform-signed launchctl as the final reboot requester on
		// iOS 18.  The custom RootHide jbctl has valid runtime entitlements, but
		// launchd can still silently decline its reboot3 request based on private
		// caller-identity policy that csops and entitlement queries do not expose.
		errno = 0;
		int gidResult = setgid(0);
		int gidErrno = errno;
		RootHideJbctlTrace("stock launchctl identity preparation; setgid=%d errno=%d uid=%d euid=%d gid=%d egid=%d",
		                   gidResult, gidErrno, getuid(), geteuid(), getgid(), getegid());

		const char *launchctlPath = "/bin/launchctl";
		if (access(launchctlPath, X_OK) != 0) launchctlPath = "/usr/bin/launchctl";
		if (access(launchctlPath, X_OK) != 0) {
			RootHideJbctlTrace("FAILURE: stock launchctl is unavailable at /bin/launchctl and /usr/bin/launchctl");
			return 72;
		}

		// systemhook's execve wrapper recognizes _SafeMode and removes its own
		// DYLD insertion before entering the stock executable.  This keeps the
		// launchctl audit identity and code-signing state entirely Apple-owned.
		unsetenv("DYLD_INSERT_LIBRARIES");
		unsetenv("DYLD_IN_CACHE");
		unsetenv("DISABLE_TWEAKS");
		unsetenv("ROOTHIDE_BOOTSTRAP_RECURSIVE_TRUST");
		unsetenv("ROOTHIDE_BOOTSTRAP_TRUST_ONLY");
		errno = 0;
		int safeModeResult = setenv("_SafeMode", "1", 1);
		int safeModeErrno = errno;
		RootHideJbctlTrace("stock launchctl environment preparation; safe_mode=%d errno=%d", safeModeResult, safeModeErrno);
		if (safeModeResult != 0) return 73;
		RootHideJbctlTrace("executing stock launchctl userspace reboot; path=%s", launchctlPath);
		char *const launchctlArgv[] = { (char *)launchctlPath, "reboot", "userspace", NULL };
		errno = 0;
		int execResult = execve(launchctlPath, launchctlArgv, environ);
		int execErrno = errno;
		unsetenv("_SafeMode");
		RootHideJbctlTrace("FAILURE: stock launchctl exec returned %d errno=%d (%s)", execResult, execErrno, strerror(execErrno));
		return 74;
	}

	usleep(10000);
	errno = 0;
	RootHideJbctlTrace("calling reboot3 with RB2_USERREBOOT");
	int result = reboot3(RB2_USERREBOOT);
	int savedErrno = errno;
	RootHideJbctlTrace("reboot3 returned %d errno=%d (%s)", result, savedErrno, strerror(savedErrno));
	return result;
}

void print_usage(void)
{
	printf("Usage: jbctl <command> <arguments>\n\
Available commands:\n\
	proc_set_debugged <pid>\t\tMarks the process with the given pid as being debugged, allowing invalid code pages inside of it\n\
	trustcache info\t\t\tPrint info about all jailbreak related trustcaches and the cdhashes contained in them\n\
	trustcache clear\t\tClears all existing cdhashes from the jailbreaks trustcache\n\
	trustcache add <cdhash>\t\tAdd an arbitrary cdhash to the jailbreaks trustcache\n\
	update <tipa/basebin/tarball> <path>\tInitiates a jailbreak update either based on a TIPA, based on a basebin.tar file or based on a standalone tarball, TIPA installation depends on TrollStore, afterwards it triggers a userspace reboot\n");
}

int main(int argc, char* argv[])
{
	if (!strcmp(argv[argc-1], "earlyboot")) {
		// If jbctl is spawned in "early boot" state, the jbserver port needs to be obtained from registeredPorts[0] instead
		mach_port_t *registeredPorts;
		mach_msg_type_number_t registeredPortsCount = 0;
		if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) == KERN_SUCCESS) {
			jbclient_xpc_set_custom_port(registeredPorts[0]);

			for(mach_msg_type_number_t i = 1; i < registeredPortsCount; i++) {
				mach_port_deallocate(mach_task_self(), registeredPorts[i]);
			}
			vm_deallocate(mach_task_self(), (vm_address_t)registeredPorts, registeredPortsCount * sizeof(mach_port_t));
		}
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) {
		print_usage();
		return 1;
	}

	if (getuid() != 0 && geteuid() == 0) {
		// When jailbroken the Dopamine app cannot have uid 0 because it can't drop it anymore without loosing it
		// So in some cases (e.g. for spawning dpkg) we need to use jbctl to get it
		setuid(0);
	}

	if (argc > 2) {
		if (!strcmp(argv[argc-2], "--waitfor")) {
			// When the Dopamine app spawns jbctl it needs to clean up it's own ucred before jbctl does the requested action
			// For this it will attach a pipe fd and write to it once the cleanup is done, so we need to wait until that write happens
			int fd = atoi(argv[argc-1]);
			int r = 0;
			read(fd, &r, sizeof(r));
			close(fd);
		}
	}

	const char *rootPath = jbclient_get_jbroot();
	if (rootPath) {
		gSystemInfo.jailbreakInfo.rootPath = strdup(rootPath);
	}

	char *cmd = argv[1];
	if (!strcmp(cmd, "proc_set_debugged")) {
		if (argc != 3) {
			print_usage();
			return 1;
		}
		int pid = atoi(argv[2]);
		int64_t result = jbclient_platform_set_process_debugged(pid, true);
		if (result == 0) {
			printf("Successfully marked proc of pid %d as debugged\n", pid);
		}
		else {
			printf("Failed to mark proc of pid %d as debugged\n", pid);
		}
	}
	else if (!strcmp(cmd, "trustcache")) {
		if (argc < 3) {
			print_usage();
			return 2;
		}
		if (getuid() != 0) {
			printf("ERROR: trustcache subcommand requires root.\n");
			return 3;
		}
		const char *trustcacheCmd = argv[2];
		if (!strcmp(trustcacheCmd, "info")) {
			xpc_object_t tcArr = nil;
			if (jbclient_root_trustcache_info(&tcArr) == 0) {
				size_t tcCount = xpc_array_get_count(tcArr);
				for (size_t i = 0; i < tcCount; i++) {
					xpc_object_t tc = xpc_array_get_dictionary(tcArr, i);
					size_t uuidLength = 0;
					const void *uuidData = xpc_dictionary_get_data(tc, "uuid", &uuidLength);
					xpc_object_t cdhashesArr = xpc_dictionary_get_array(tc, "cdhashes");
					if (uuidData && cdhashesArr) {
						size_t length = xpc_array_get_count(cdhashesArr);
						char uuidString[uuidLength * 2 + 1];
						convert_data_to_hex_string(uuidData, uuidLength, uuidString);
						printf("Jailbreak Trustcache %zd <UUID: %s> (length: %zd)\n", i, uuidString, length);
						for (size_t j = 0; j < length; j++) {
							size_t cdhashLength = 0;
							const void *cdhashData = xpc_array_get_data(cdhashesArr, j, &cdhashLength);
							if (cdhashData) {
								char cdhashString[cdhashLength * 2 + 1];
								convert_data_to_hex_string(cdhashData, cdhashLength, cdhashString);
								printf("| %zd:\t%s\n", j+1, cdhashString);
							}
						}
					}
				}
			}
			return 0;
		}
		else if (!strcmp(trustcacheCmd, "clear")) {
			return jbclient_root_trustcache_clear();
		}
		else if (!strcmp(trustcacheCmd, "add")) {
			if (argc < 4) {
				print_usage();
				return 2;
			}
			const char *cdhashString = argv[3];
			if (strlen(cdhashString) != (sizeof(cdhash_t) * 2)) {
				printf("ERROR: passed cdhash has wrong length\n");
				return 2;
			}
			cdhash_t cdhash;
			if (convert_hex_string_to_data(cdhashString, &cdhash)) {
				printf("ERROR: passed cdhash is malformed\n");
				return 2;
			}
			return jbclient_root_trustcache_add_cdhash(cdhash, sizeof(cdhash));
		}
	}
	else if (!strcmp(cmd, "reboot_userspace")) {
		return PerformUserspaceReboot();
	}
	else if (!strcmp(cmd, "respring")) {
		usleep(10000);
		const char *sbreloadPath = JBROOT_PATH("/usr/bin/sbreload");
		if (execve(sbreloadPath, (char *[]){ (char *)sbreloadPath, NULL }, environ) != 0) {
			killall("/usr/libexec/backboardd", SIGTERM);
		}
	}
	else if (!strcmp(cmd, "update")) {
		if (argc < 4) {
			print_usage();
			return 2;
		}
		char *updateType = argv[2];
		char *updateFile = argv[3];
		if (access(updateFile, F_OK) != 0) {
			printf("ERROR: File %s does not exist\n", updateFile);
			return 3;
		}

		if (!strcmp(updateType, "tipa")) {
			setsid();

			LSApplicationProxy *trollstoreAppProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.TrollStore"];
			if (!trollstoreAppProxy || !trollstoreAppProxy.installed) {
				printf("Unable to locate TrollStore, doesn't seem like it's installed.\n");
				return 4;
			}
			NSString *trollstorehelperPath = [trollstoreAppProxy.bundleURL.path stringByAppendingPathComponent:@"trollstorehelper"];
			int r = exec_cmd(trollstorehelperPath.fileSystemRepresentation, "install", "skip-uicache", "force", updateFile, NULL);
			if (r != 0) {
				printf("Failed to install tipa via TrollStore: %d\n", r);
				return 5;
			}

			LSApplicationProxy *dopamineAppProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.Dopamine"];
			if (!dopamineAppProxy) {
				printf("Unable to locate newly installed Dopamine build.\n");
				return 6;
			}
			updateFile = strdup([dopamineAppProxy.bundleURL.path stringByAppendingPathComponent:@"basebin.tar"].fileSystemRepresentation);
			// Fall through to basebin installation
		}
		else if (!strcmp(updateType, "tarball")) {
			NSString *tmpPath = [@"/tmp" stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
			[[NSFileManager defaultManager] createDirectoryAtPath:tmpPath withIntermediateDirectories:NO attributes:nil error:nil];
			int r = libarchive_unarchive(updateFile, tmpPath.fileSystemRepresentation);
			if (r != 0) {
				printf("Failed to extract tarball: %d\n", r);
				return 7;
			}
			updateFile = strdup([tmpPath stringByAppendingPathComponent:@"basebin.tar"].fileSystemRepresentation);
			// Fall through to basebin installation
		}
		else if (strcmp(updateType, "basebin") != 0) {
			// If type is not tipa, tarball or basebin, bail out
			print_usage();
			return 2;
		}

		int64_t result = jbclient_platform_stage_jailbreak_update(updateFile);
		if (result == 0) {
			printf("Staged update for installation during the next userspace reboot, userspace rebooting now...\n");
			return PerformUserspaceReboot();
		}
		else {
			printf("Staging update failed with error code %lld\n", result);
			return result;
		}
	}
	else if (!strcmp(cmd, "internal")) {
		if (getuid() != 0) return 41;
		if (argc < 3) return 42;

		const char *internalCmd = argv[2];
		return jbctl_handle_internal(internalCmd, argc-2, &argv[2]);
	}

	return 0;
}
