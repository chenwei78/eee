#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/jbclient_mach.h>
#import <libjailbreak/stock_fixes.h>
#import <libjailbreak/watchdog_reboot.h>
#import "internal.h"

#import <Foundation/Foundation.h>
#import <CoreServices/LSApplicationProxy.h>

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <notify.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include <xpc_private.h>

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

static int RootHideBooleanEntitlementForPid(pid_t pid, const char *entitlement, bool traceFailure)
{
	if (pid <= 1 || !entitlement) return -1;

	mach_port_t task = MACH_PORT_NULL;
	kern_return_t taskResult = task_for_pid(mach_task_self(), pid, &task);
	if (taskResult != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
		if (traceFailure) {
			RootHideJbctlTrace("entitlement probe task_for_pid failed; pid=%d result=%d task=%x",
			                   pid, taskResult, task);
		}
		return -1;
	}

	audit_token_t auditToken = {0};
	mach_msg_type_number_t tokenCount = TASK_AUDIT_TOKEN_COUNT;
	kern_return_t tokenResult = task_info(task, TASK_AUDIT_TOKEN,
	                                      (task_info_t)&auditToken, &tokenCount);
	mach_port_deallocate(mach_task_self(), task);
	if (tokenResult != KERN_SUCCESS || tokenCount < TASK_AUDIT_TOKEN_COUNT) {
		if (traceFailure) {
			RootHideJbctlTrace("entitlement probe TASK_AUDIT_TOKEN failed; pid=%d result=%d count=%u expected=%u",
			                   pid, tokenResult, tokenCount, (unsigned int)TASK_AUDIT_TOKEN_COUNT);
		}
		return -1;
	}

	xpc_object_t value = xpc_copy_entitlement_for_token(entitlement, &auditToken);
	if (!value) {
		if (traceFailure) {
			RootHideJbctlTrace("entitlement probe returned no value; pid=%d entitlement=%s", pid, entitlement);
		}
		return 0;
	}
	int result = xpc_get_type(value) == XPC_TYPE_BOOL && xpc_bool_get_value(value) ? 1 : 0;
	return result;
}

static bool RootHideVerifyMaintenanceRebootHost(pid_t pid, bool allowDirectChild, bool traceCandidate)
{
	if (pid <= 1) return false;

	char processPath[PATH_MAX] = {0};
	if (proc_pidpath(pid, processPath, sizeof(processPath)) <= 0 ||
	    strcmp(processPath, "/usr/libexec/mmaintenanced") != 0) {
		return false;
	}

	struct proc_bsdinfo bsdInfo = {0};
	int bsdInfoResult = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0,
	                                     &bsdInfo, sizeof(bsdInfo));
	uint32_t csFlags = 0;
	int csResult = csops(pid, CS_OPS_STATUS, &csFlags, sizeof(csFlags));
	int rebootEntitlement = RootHideBooleanEntitlementForPid(
		pid, "com.apple.private.xpc.launchd.userspace-reboot", traceCandidate);
	bool platform = csResult == 0 && (csFlags & CS_PLATFORM_BINARY) != 0;
	bool expectedParent = bsdInfoResult == sizeof(bsdInfo) &&
		(bsdInfo.pbi_ppid == 1 || (allowDirectChild && bsdInfo.pbi_ppid == getpid()));
	if (traceCandidate) {
		RootHideJbctlTrace("mmaintenanced candidate; pid=%d ppid=%d bsdinfo=%d csops=%d csflags=0x%08x platform=%d reboot_entitlement=%d direct=%d",
		                   pid, bsdInfo.pbi_ppid, bsdInfoResult, csResult, csFlags,
		                   platform, rebootEntitlement, allowDirectChild);
	}
	return expectedParent && platform && rebootEntitlement == 1;
}

static pid_t RootHideFindMaintenanceRebootHost(void)
{
	int requiredBytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	RootHideJbctlTrace("mmaintenanced process enumeration sizing returned %d", requiredBytes);
	if (requiredBytes <= 0 || requiredBytes > INT_MAX - (int)(64 * sizeof(pid_t))) return -1;

	int bufferSize = requiredBytes + (int)(64 * sizeof(pid_t));
	pid_t *pids = calloc(1, (size_t)bufferSize);
	if (!pids) return -1;

	int returnedBytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bufferSize);
	if (returnedBytes <= 0) {
		free(pids);
		return -1;
	}

	pid_t maintenancePid = -1;
	int pidCount = returnedBytes / (int)sizeof(pid_t);
	for (int i = 0; i < pidCount; i++) {
		pid_t pid = pids[i];
		if (pid <= 1) continue;

		if (RootHideVerifyMaintenanceRebootHost(pid, false, true)) {
			maintenancePid = pid;
			break;
		}
	}
	free(pids);

	RootHideJbctlTrace("mmaintenanced reboot host lookup returned pid=%d listed_bytes=%d",
	                   maintenancePid, returnedBytes);
	return maintenancePid;
}

static pid_t RootHideStartMaintenanceRebootHost(void)
{
	const char *maintenancePath = "/usr/libexec/mmaintenanced";
	if (access(maintenancePath, X_OK) != 0) {
		RootHideJbctlTrace("FAILURE: native mmaintenanced is unavailable at %s", maintenancePath);
		return -1;
	}

	char *environment[] = {
		(char *)"_SafeMode=1",
		(char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		NULL,
	};
	char *arguments[] = {(char *)maintenancePath, NULL};
	posix_spawnattr_t attributes = NULL;
	if (posix_spawnattr_init(&attributes) != 0) {
		RootHideJbctlTrace("FAILURE: could not initialize native mmaintenanced spawn attributes");
		return -1;
	}
	short flags = 0;
	posix_spawnattr_getflags(&attributes, &flags);
	posix_spawnattr_setflags(&attributes, flags | POSIX_SPAWN_START_SUSPENDED);

	// This is a stock system daemon.  Keep it out of RootHide child patching;
	// the bridge is installed explicitly below after the process is verified.
	exec_set_patch(false);
	exec_set_bootstrap_trust_only(false);
	pid_t spawnedPid = -1;
	int spawnResult = exec_cmd_roothide_spawn(&spawnedPid, maintenancePath, NULL,
	                                           &attributes, arguments, environment);
	exec_set_patch(true);
	posix_spawnattr_destroy(&attributes);
	RootHideJbctlTrace("native mmaintenanced direct spawn returned %d pid=%d", spawnResult, spawnedPid);
	if (spawnResult != 0 || spawnedPid <= 1) return -1;

	if (kill(spawnedPid, SIGCONT) != 0) {
		RootHideJbctlTrace("FAILURE: could not resume native mmaintenanced pid=%d errno=%d",
		                   spawnedPid, errno);
		(void)kill(spawnedPid, SIGKILL);
		(void)waitpid(spawnedPid, NULL, 0);
		return -1;
	}
	RootHideJbctlTrace("native mmaintenanced direct child resumed; pid=%d", spawnedPid);

	for (int attempt = 1; attempt <= 40; attempt++) {
		if (RootHideVerifyMaintenanceRebootHost(spawnedPid, true, false)) {
			RootHideJbctlTrace("native mmaintenanced direct child verified after %d attempt(s); pid=%d",
			                   attempt, spawnedPid);
			return spawnedPid;
		}

		int status = 0;
		pid_t waitResult = waitpid(spawnedPid, &status, WNOHANG);
		if (waitResult == spawnedPid) {
			RootHideJbctlTrace("FAILURE: native mmaintenanced direct child exited; pid=%d status=%d",
			                   spawnedPid, status);
			return -1;
		}
		usleep(25000);
	}

	(void)RootHideVerifyMaintenanceRebootHost(spawnedPid, true, true);
	RootHideJbctlTrace("FAILURE: native mmaintenanced direct child did not pass verification; pid=%d",
	                   spawnedPid);
	(void)kill(spawnedPid, SIGKILL);
	(void)waitpid(spawnedPid, NULL, 0);
	return -1;
}

static int RootHideRequestMaintenanceUserspaceReboot(void)
{
	pid_t rebootHostPid = RootHideFindMaintenanceRebootHost();
	if (rebootHostPid <= 1) {
		RootHideJbctlTrace("mmaintenanced is not running as a verified launchd child; starting native fallback");
		rebootHostPid = RootHideStartMaintenanceRebootHost();
		if (rebootHostPid <= 1) {
			RootHideJbctlTrace("FAILURE: no verified /usr/libexec/mmaintenanced reboot host is available");
			return 72;
		}
	}

	const char *opainjectPath = JBROOT_PATH("/basebin/opainject");
	const char *watchdogRebootPath = JBROOT_PATH("/basebin/watchdogreboot.dylib");
	if (!opainjectPath || access(opainjectPath, X_OK) != 0) {
		RootHideJbctlTrace("FAILURE: opainject is unavailable at %s", opainjectPath ?: "(null)");
		return 73;
	}
	if (!watchdogRebootPath || access(watchdogRebootPath, R_OK) != 0) {
		RootHideJbctlTrace("FAILURE: userspace-reboot bridge is unavailable at %s", watchdogRebootPath ?: "(null)");
		return 74;
	}

	int readyToken = -1;
	uint32_t readyRegisterResult = notify_register_check(
		ROOTHIDE_WATCHDOG_REBOOT_READY_NOTIFICATION, &readyToken);
	RootHideJbctlTrace("reboot-host readiness registration returned %u token=%d",
	                   readyRegisterResult, readyToken);
	if (readyRegisterResult != NOTIFY_STATUS_OK) {
		RootHideJbctlTrace("FAILURE: reboot-host readiness registration returned %u", readyRegisterResult);
		return 75;
	}

	int changed = 0;
	(void)notify_check(readyToken, &changed); // Discard notifications from an earlier attempt.

	char rebootHostPidString[32] = {0};
	snprintf(rebootHostPidString, sizeof(rebootHostPidString), "%d", rebootHostPid);
	RootHideJbctlTrace("injecting userspace-reboot bridge into mmaintenanced; pid=%d path=%s",
	                   rebootHostPid, watchdogRebootPath);
	// opainject must start without systemhook or jailbreakd child patching.  It
	// manipulates thread state itself, and pre-main injection crashes the helper
	// before it can create its arm64e PAC child.  _SafeMode is consumed by the
	// systemhook spawn wrapper, so it suppresses injection without leaking into
	// opainject itself.
	char traceEnvironment[PATH_MAX + 32] = {0};
	char *cleanEnvironment[] = {
		(char *)"_SafeMode=1",
		(char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		NULL,
		NULL,
	};
	const char *tracePath = getenv("ROOTHIDE_JBCTL_TRACE_PATH");
	if (tracePath && tracePath[0]) {
		int traceLength = snprintf(traceEnvironment, sizeof(traceEnvironment),
		                           "ROOTHIDE_JBCTL_TRACE_PATH=%s", tracePath);
		if (traceLength > 0 && (size_t)traceLength < sizeof(traceEnvironment)) {
			cleanEnvironment[2] = traceEnvironment;
		}
	}
	exec_set_bootstrap_trust_only(true);
	int injectionResult = exec_cmd_env(cleanEnvironment, opainjectPath,
	                                   rebootHostPidString, watchdogRebootPath, NULL);
	exec_set_bootstrap_trust_only(false);
	RootHideJbctlTrace("mmaintenanced reboot bridge injection returned %d", injectionResult);
	if (injectionResult != 0) {
		notify_cancel(readyToken);
		RootHideJbctlTrace("FAILURE: mmaintenanced reboot bridge injection returned %d", injectionResult);
		return 76;
	}

	uint32_t pingResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_PING_NOTIFICATION);
	RootHideJbctlTrace("reboot-host readiness probe post returned %u", pingResult);
	if (pingResult != NOTIFY_STATUS_OK) {
		notify_cancel(readyToken);
		RootHideJbctlTrace("FAILURE: reboot-host readiness probe post returned %u", pingResult);
		return 77;
	}

	int readyAttempt = 0;
	uint32_t readyCheckResult = NOTIFY_STATUS_OK;
	for (int attempt = 1; attempt <= 40; attempt++) {
		changed = 0;
		readyCheckResult = notify_check(readyToken, &changed);
		if (readyCheckResult != NOTIFY_STATUS_OK || changed != 0) {
			readyAttempt = changed != 0 ? attempt : 0;
			break;
		}
		usleep(25000);
	}
	notify_cancel(readyToken);
	if (readyCheckResult != NOTIFY_STATUS_OK || readyAttempt == 0) {
		RootHideJbctlTrace("FAILURE: reboot-host notification channel did not become ready; check_result=%u",
		                   readyCheckResult);
		return 78;
	}
	RootHideJbctlTrace("reboot-host notification channel ready after %d attempt(s)", readyAttempt);

	int receivedToken = -1;
	uint32_t receivedRegisterResult = notify_register_check(
		ROOTHIDE_WATCHDOG_REBOOT_RECEIVED_NOTIFICATION, &receivedToken);
	RootHideJbctlTrace("reboot-host request acknowledgement registration returned %u token=%d",
	                   receivedRegisterResult, receivedToken);
	if (receivedRegisterResult != NOTIFY_STATUS_OK) {
		RootHideJbctlTrace("FAILURE: reboot-host request acknowledgement registration returned %u",
		                   receivedRegisterResult);
		return 79;
	}
	changed = 0;
	(void)notify_check(receivedToken, &changed);
	int resultToken = -1;
	uint32_t resultRegisterResult = notify_register_check(
		ROOTHIDE_WATCHDOG_REBOOT_RESULT_NOTIFICATION, &resultToken);
	RootHideJbctlTrace("reboot-host reboot result registration returned %u token=%d",
	                   resultRegisterResult, resultToken);
	if (resultRegisterResult != NOTIFY_STATUS_OK) {
		notify_cancel(receivedToken);
		RootHideJbctlTrace("FAILURE: reboot-host reboot result registration returned %u",
		                   resultRegisterResult);
		return 80;
	}
	changed = 0;
	(void)notify_check(resultToken, &changed);
	uint32_t resetStateResult = notify_set_state(resultToken, UINT64_MAX);
	RootHideJbctlTrace("reboot-host reboot result state reset returned %u", resetStateResult);
	if (resetStateResult != NOTIFY_STATUS_OK) {
		notify_cancel(receivedToken);
		notify_cancel(resultToken);
		RootHideJbctlTrace("FAILURE: reboot-host reboot result state reset returned %u", resetStateResult);
		return 81;
	}

	RootHideJbctlTrace("posting userspace-reboot request to mmaintenanced pid=%d", rebootHostPid);
	uint32_t requestResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_NOTIFICATION);
	RootHideJbctlTrace("reboot-host userspace-reboot notification post returned %u", requestResult);
	if (requestResult != NOTIFY_STATUS_OK) {
		notify_cancel(receivedToken);
		notify_cancel(resultToken);
		RootHideJbctlTrace("FAILURE: reboot-host userspace-reboot notification post returned %u", requestResult);
		return 82;
	}

	int receivedAttempt = 0;
	uint32_t receivedCheckResult = NOTIFY_STATUS_OK;
	for (int attempt = 1; attempt <= 40; attempt++) {
		changed = 0;
		receivedCheckResult = notify_check(receivedToken, &changed);
		if (receivedCheckResult != NOTIFY_STATUS_OK || changed != 0) {
			receivedAttempt = changed != 0 ? attempt : 0;
			break;
		}
		usleep(25000);
	}
	notify_cancel(receivedToken);
	if (receivedCheckResult != NOTIFY_STATUS_OK || receivedAttempt == 0) {
		notify_cancel(resultToken);
		RootHideJbctlTrace("FAILURE: reboot-host did not acknowledge the userspace-reboot request; check_result=%u",
		                   receivedCheckResult);
		return 83;
	}
	RootHideJbctlTrace("reboot-host acknowledged userspace-reboot request after %d attempt(s)", receivedAttempt);

	int resultAttempt = 0;
	uint32_t resultCheckResult = NOTIFY_STATUS_OK;
	uint32_t getStateResult = NOTIFY_STATUS_OK;
	uint64_t resultState = UINT64_MAX;
	for (int attempt = 1; attempt <= 40; attempt++) {
		changed = 0;
		resultCheckResult = notify_check(resultToken, &changed);
		if (resultCheckResult != NOTIFY_STATUS_OK) break;
		if (changed != 0) {
			getStateResult = notify_get_state(resultToken, &resultState);
			if (getStateResult != NOTIFY_STATUS_OK) break;
			// notify_check may report false positives.  Only accept a value that
			// replaced the sentinel written immediately before this request.
			if (resultState != UINT64_MAX) {
				resultAttempt = attempt;
				break;
			}
		}
		usleep(25000);
	}
	notify_cancel(resultToken);
	if (resultCheckResult == NOTIFY_STATUS_OK &&
	    getStateResult == NOTIFY_STATUS_OK &&
	    resultAttempt != 0) {
		int rebootResult = (int)(int32_t)(resultState >> 32);
		int rebootErrno = (int)(uint32_t)resultState;
		RootHideJbctlTrace("reboot-host reboot3 result returned %d errno=%d; get_state=%u attempt=%d",
		                   rebootResult, rebootErrno, getStateResult, resultAttempt);
		if (rebootResult != 0) {
			RootHideJbctlTrace("FAILURE: reboot-host reboot3 returned %d errno=%d", rebootResult, rebootErrno);
			return 85;
		}
	}
	else {
		RootHideJbctlTrace("FAILURE: reboot-host reboot3 result was not observed; check_result=%u get_state=%u",
		                   resultCheckResult, getStateResult);
		return 84;
	}
	return 0;
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
		return RootHideRequestMaintenanceUserspaceReboot();
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
