#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <libproc.h>
#include <xpc_private.h>
#include "jbserver_global.h"

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>
#include "../roothide_trace.h"
#include "../spawn_hook.h"

int roothide_unsupport_request()
{
	JBLogError("**************************** Unsupported request ****************************");
	return -1;
}

bool roothide_domain_allowed(audit_token_t clientToken)
{
	//its fast enough
	if(isBlacklistedToken(&clientToken)) {
		JBLogDebug("ignore xpc message from blacklisted process (%d),%s", audit_token_to_pid(clientToken), proc_get_path(audit_token_to_pid(clientToken),NULL));
		return false;
	}

	return true;
}

static int roothide_entitlement_bool(audit_token_t *clientToken, const char *entitlement)
{
	xpc_object_t value = xpc_copy_entitlement_for_token(entitlement, clientToken);
	if (!value) return -1;

	int result = -1;
	if (xpc_get_type(value) == XPC_TYPE_BOOL) {
		result = xpc_bool_get_value(value) ? 1 : 0;
	}
	xpc_release(value);
	return result;
}

static int roothide_read_csflags(audit_token_t *clientToken, uint32_t *csFlags)
{
	pid_t pid = audit_token_to_pid(*clientToken);
	int result = csops_audittoken(pid, CS_OPS_STATUS, csFlags, sizeof(*csFlags), clientToken);
	if (result != 0) {
		// Keep the ordinary csops fallback for SDK/runtime combinations where
		// csops_audittoken is unavailable, while the path check below still
		// prevents a recycled PID from being trusted blindly.
		result = csops(pid, CS_OPS_STATUS, csFlags, sizeof(*csFlags));
	}
	return result;
}

typedef struct {
	uint32_t Count;
	uint32_t* Types;
	uint32_t* Subtypes;
} preferredArchInfo;
void recurse_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, const char *workingDir, preferredArchInfo* preferredArch, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);

static int trust_macho_recurse(const char *machoPath, const char *dlopenCallerImagePath, const char *dlopenCallerExecutablePath, const char *workingDir, xpc_object_t preferredArchsArray)
{
	if(!machoPath || !dlopenCallerExecutablePath) return -1;
	
	size_t preferredArchCount = 0;
	if (preferredArchsArray) preferredArchCount = xpc_array_get_count(preferredArchsArray);
	uint32_t preferredArchTypes[preferredArchCount];
	uint32_t preferredArchSubtypes[preferredArchCount];
	for (size_t i = 0; i < preferredArchCount; i++) {
		preferredArchTypes[i] = 0;
		preferredArchSubtypes[i] = UINT32_MAX;
		xpc_object_t arch = xpc_array_get_value(preferredArchsArray, i);
		if (xpc_get_type(arch) == XPC_TYPE_DICTIONARY) {
			preferredArchTypes[i] = xpc_dictionary_get_uint64(arch, "type");
			preferredArchSubtypes[i] = xpc_dictionary_get_uint64(arch, "subtype");
		}
	}
	
	preferredArchInfo preferredArch = {preferredArchCount, preferredArchTypes, preferredArchSubtypes};

	cdhash_t *cdhashes = NULL;
	uint32_t cdhashesCount = 0;
	recurse_collect_untrusted_cdhashes(machoPath, dlopenCallerImagePath, dlopenCallerExecutablePath, workingDir, &preferredArch, &cdhashes, &cdhashesCount);
	if (cdhashes && cdhashesCount > 0) {
		int trustResult = jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
		free(cdhashes);
		return trustResult;
	}
	return 0;
}

int roothide_trust_executable_recurse(const char *executablePath, const char *processWorkingDir, xpc_object_t preferredArchsArray)
{
	return trust_macho_recurse(executablePath, NULL, executablePath, processWorkingDir, preferredArchsArray);
}

static int roothide_trust_library_recurse(const char *libraryPath, const char *callerLibraryPath, const char *callerExecutablePath, const char *currentWorkingDir)
{
	// When trusting a library that's dlopened at runtime, we need to pass the caller path
	// This is to support dlopen("@executable_path/whatever", RTLD_NOW) and stuff like that
	// (Yes that is a thing >.<)
	// Also we need to pass the path of the image that called dlopen due to @loader_path, sigh...
	return trust_macho_recurse(libraryPath, callerLibraryPath, callerExecutablePath, currentWorkingDir, NULL);
}

static int roothide_jailbroken_check(audit_token_t *callerToken, bool* jailbroken)
{
	// launchdhook is already active while the first RootHide bootstrap is
	// being installed.  Only report success after the bootstrapper has
	// completed all of its setup steps and written its completion marker.
	*jailbroken = access(JBROOT_PATH("/.roothide_bootstrap_complete"), F_OK) == 0 && jailbreakdIsReady();
	return 0;
}

static int roothide_palehide_present(audit_token_t *callerToken, bool* palehide)
{
	static bool result = false;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		if(jbinfo(palera1n)=='hide') {
			result = true;
		} else {
			// hang forver on iphone7p ios15.8.2
			// mach_port_t tfp0 = MACH_PORT_NULL;
			// kern_return_t kr = task_for_pid(mach_task_self(), 0, &tfp0);
			// if(kr == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
			// 	mach_port_deallocate(mach_task_self(), tfp0);
			// 	result = true;
			// }
		}
	});

	*palehide = result;
	return 0;
}

static int roothide_blacklist_check(audit_token_t *callerToken, const char* checktype, xpc_object_t checkvalue, bool* blacklisted)
{
	if(strcmp(checktype, "pid")==0) {
		pid_t pid = (pid_t)xpc_uint64_get_value(checkvalue);
		if(pid > 1) {
			*blacklisted = isBlacklistedPid(pid);
			return 0;
		}
	} else if(strcmp(checktype, "path")==0) {
		const char* path = xpc_string_get_string_ptr(checkvalue);
		if(path) {
			*blacklisted = isBlacklistedPath(path);
			return 0;
		}
	} else if(strcmp(checktype, "bundle")==0) {
		const char* bundle = xpc_string_get_string_ptr(checkvalue);
		if(bundle) {
			*blacklisted = isBlacklistedApp(bundle);
			return 0;
		}
	} else {
		JBLogError("Invalid checktype: %s", checktype);
		return -1;
	}
	JBLogError("Failed to check blacklist for %s : %s", checktype, xpc_type_get_name(xpc_get_type(checkvalue)));
	return -1;
}

static int roothide_jailbreakd_lookup(audit_token_t *callerToken, xpc_object_t *portOut)
{
	// During the first live injection launchd is executing inside opainject's
	// ROP call, so roothide_launchd_postinit deliberately defers jailbreakd.
	// This XPC handler only runs after the constructor returned and launchd's
	// normal threads have resumed; it is therefore the safe point to start it.
    roothide_trace("[launchd] jailbreakd lookup from pid=%d; initialized=%d", audit_token_to_pid(*callerToken), jailbreakdIsInitialized());
	if (jailbreakdIsStoppingForUserspaceReboot()) {
		roothide_trace("[launchd] jailbreakd lookup declined during userspace-reboot teardown");
		return -4;
	}

	if (!jailbreakdIsInitialized()) {
        roothide_trace("[launchd] starting deferred jailbreakd");
        int initResult = initJailbreakd(true);
        roothide_trace("[launchd] deferred jailbreakd start returned %d", initResult);
        if (initResult != 0) return -1;
    }

    // A newly spawned jailbreakd has to check in and receive its server port
    // before clients send it a synchronous patch request.  Returning no port
    // here lets the caller retry without blocking forever on an unready port.
    if (!jailbreakdIsReady()) {
        int exitStatus = 0;
        if (jailbreakdConsumeExitStatus(&exitStatus)) {
            if (WIFEXITED(exitStatus)) {
                roothide_trace("[launchd] FAILURE: jailbreakd exited before check-in with code %d (raw status %d)", WEXITSTATUS(exitStatus), exitStatus);
            }
            else if (WIFSIGNALED(exitStatus)) {
                roothide_trace("[launchd] FAILURE: jailbreakd terminated before check-in by signal %d (raw status %d)", WTERMSIG(exitStatus), exitStatus);
            }
            else {
                roothide_trace("[launchd] FAILURE: jailbreakd stopped before check-in (raw status %d)", exitStatus);
            }
            return -3;
        }
        roothide_trace("[launchd] jailbreakd is starting; check-in not complete yet");
        return -2;
    }

    mach_port_t port = jailbreakdClientPort();
    if (!MACH_PORT_VALID(port)) {
        roothide_trace("[launchd] jailbreakd lookup failed: invalid client port");
        return -1;
    }
    roothide_trace("[launchd] jailbreakd lookup returned a client port");
	*portOut = xpc_mach_send_create(port);
	return 0;
}

static int roothide_jailbreakd_checkin(audit_token_t *callerToken, xpc_object_t *portOut)
{
	pid_t pid = audit_token_to_pid(*callerToken);
	uid_t uid = audit_token_to_euid(*callerToken);

	if(uid != 0) return -1;

	setJailbreakdProcess(pid);
	jailbreakdSetReady();
	roothide_trace("[launchd] jailbreakd checked in from pid=%d", pid);

	*portOut = xpc_mach_recv_create(jailbreakdServerPort());
	return 0;
}

static int roothide_dyld_patch_enabled(audit_token_t *callerToken, bool* enabled)
{
	*enabled = jbinfo(dyld_patch_enabled);
	return 0;
}

static int roothide_set_dyld_patch(audit_token_t *callerToken, bool enabled)
{
	pid_t pid = audit_token_to_pid(*callerToken);
	uid_t uid = audit_token_to_euid(*callerToken);

    uint32_t csFlags = 0;
    csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));

	if(uid != 0 && (csFlags & CS_PLATFORM_BINARY)==0) {
		JBLogError("roothide_set_dyld_patch: denying request from %d,%d", pid, uid);
		return -1;
	}
	
#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		if(roothide_config_set_spinlock_fix(enabled) != 0) {
			JBLogError("roothide_config_set_spinlock_fix failed");
			return -1;
		}
	}
#endif

	jbinfo(dyld_patch_enabled) = enabled;
	
	return 0;
}

static int roothide_prepare_userspace_reboot(audit_token_t *callerToken)
{
	pid_t callerPid = audit_token_to_pid(*callerToken);
	uid_t callerUid = audit_token_to_euid(*callerToken);
	if (callerUid != 0) {
		roothide_trace("[launchd] FAILURE: denied userspace-reboot preparation from pid=%d euid=%d", callerPid, callerUid);
		return -1;
	}

	char callerPath[PATH_MAX] = {0};
	int callerPathResult = proc_pidpath_audittoken(callerToken, callerPath, sizeof(callerPath));
	bool expectedCaller = callerPathResult > 0 && string_has_suffix(callerPath, "/basebin/jbctl");
	if (!expectedCaller) {
		roothide_trace("[launchd] FAILURE: denied userspace-reboot preparation from unexpected path; pid=%d path_result=%d path=%s",
		               callerPid, callerPathResult, callerPath[0] ? callerPath : "(unavailable)");
		return -5;
	}

	uint32_t csFlagsBefore = 0;
	int csopsBefore = roothide_read_csflags(callerToken, &csFlagsBefore);
	int platformEntitlement = roothide_entitlement_bool(callerToken, "platform-application");
	int rebootEntitlement = roothide_entitlement_bool(callerToken, "com.apple.private.xpc.launchd.userspace-reboot");
	int watchdogEntitlement = roothide_entitlement_bool(callerToken, "com.apple.private.iowatchdog.user-access");
	roothide_trace("[launchd] userspace-reboot caller authorization before repair; path=%s csops=%d csflags=0x%08x platform=%d platform_entitlement=%d reboot_entitlement=%d watchdog_entitlement=%d",
	               callerPath, csopsBefore, csFlagsBefore,
	               csopsBefore == 0 && (csFlagsBefore & CS_PLATFORM_BINARY) != 0,
	               platformEntitlement, rebootEntitlement, watchdogEntitlement);

	// RootHide rewrites and re-trusts BaseBin executables.  On iOS 18 that can
	// leave jbctl running as uid 0 while CS_PLATFORM_BINARY is absent, in which
	// case reboot3 successfully sends its XPC message but launchd silently
	// refuses to begin userspace teardown.  Repair the live caller while it is
	// blocked in this synchronous preflight request, then verify through its
	// original audit token before allowing the reboot request to be sent.
	if (csopsBefore != 0 || (csFlagsBefore & CS_PLATFORM_BINARY) == 0) {
		uint64_t callerProc = proc_find(callerPid);
		if (!callerProc) {
			roothide_trace("[launchd] FAILURE: could not resolve jbctl proc for userspace-reboot authorization repair; pid=%d", callerPid);
			return -6;
		}
		proc_csflags_set(callerProc, CS_PLATFORM_BINARY);
	}

	uint32_t csFlagsAfter = 0;
	int csopsAfter = roothide_read_csflags(callerToken, &csFlagsAfter);
	bool callerIsPlatform = csopsAfter == 0 && (csFlagsAfter & CS_PLATFORM_BINARY) != 0;
	roothide_trace("[launchd] userspace-reboot caller authorization after repair; csops=%d csflags=0x%08x platform=%d mode=%s",
	               csopsAfter, csFlagsAfter, callerIsPlatform,
	               rebootEntitlement == 1 ? "entitlement" : "platform-fallback");
	if (!callerIsPlatform) {
		roothide_trace("[launchd] FAILURE: jbctl is still not a platform process after userspace-reboot authorization repair");
		return -7;
	}

	int spawnHookResult = spawn_hook_install_result();
	roothide_trace("[launchd] userspace-reboot preflight requested by pid=%d; spawn_hook=%d",
	               callerPid, spawnHookResult);
	if (spawnHookResult != KERN_SUCCESS) {
		roothide_trace("[launchd] FAILURE: refusing userspace reboot because the spawn hook is not installed");
		return -2;
	}

	if (__builtin_available(iOS 18.0, *)) {
		// The working Dopamine 3.x transition on this OS replaces launchd through
		// __posix_spawn(POSIX_SPAWN_SETEXEC).  Avoid patching an additional libc
		// entry point in PID 1 immediately before teardown when no runtime evidence
		// has shown launchd using it.
		roothide_trace("[launchd] phase skipped: speculative execve hook on iOS 18; using verified posix_spawn transition path");
	}
	else {
		// Retain the older diagnostic coverage outside the iOS 18 target.
		int execHookResult = exec_hook_ensure_installed();
		if (execHookResult != KERN_SUCCESS) {
			roothide_trace("[launchd] FAILURE: refusing userspace reboot because deferred execve hook installation returned %d", execHookResult);
			return -3;
		}
	}

	// The live-injection jailbreakd is an extra PID 1 child that does not exist
	// in the working rootless flow. Stop and reap it before iOS 18 begins
	// userspace teardown, removing that extra process from the transition.
	if (__builtin_available(iOS 18.0, *)) {
		pid_t jailbreakdPid = -1;
		int jailbreakdStatus = -1;
		roothide_trace("[launchd] phase: stopping temporary jailbreakd before userspace reboot");
		int stopResult = jailbreakdStopForUserspaceReboot(&jailbreakdPid, &jailbreakdStatus);
		bool statusValid = jailbreakdStatus >= 0;
		bool exited = statusValid && WIFEXITED(jailbreakdStatus);
		bool signaled = statusValid && WIFSIGNALED(jailbreakdStatus);
		roothide_trace("[launchd] temporary jailbreakd stop returned %d; pid=%d status_valid=%d status=%d exited=%d exit_code=%d signaled=%d signal=%d",
		               stopResult, jailbreakdPid, statusValid, jailbreakdStatus,
		               exited, exited ? WEXITSTATUS(jailbreakdStatus) : -1,
		               signaled, signaled ? WTERMSIG(jailbreakdStatus) : 0);
		if (stopResult != 0) {
			roothide_trace("[launchd] FAILURE: refusing userspace reboot because temporary jailbreakd teardown failed");
			return -4;
		}
		roothide_trace("[launchd] phase complete: temporary jailbreakd stopped before userspace reboot");
	}

	// Primitive stashing deliberately remains in the final self-spawn/self-exec
	// hook.  A persistent boomerang child must not exist during service teardown.
	roothide_trace("[launchd] phase complete: userspace-reboot preflight; primitive stashing deferred to launchd replacement");
	return 0;
}

struct jbserver_domain gRootHideDomain = {
	.permissionHandler = roothide_domain_allowed,
	.actions = {
		//JBS_ROOTHIDE_JAILBROKEN_CHECK
        {
            .handler = roothide_jailbroken_check,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "jailbroken", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_PALEHIDE_PRESENT
        {
            .handler = roothide_palehide_present,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "palehide", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_BLACKLIST_CHECK
        {
            .handler = roothide_blacklist_check,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
					{ .name = "checktype", .type = JBS_TYPE_STRING, .out = false },
					{ .name = "checkvalue", .type = JBS_TYPE_XPC_GENERIC, .out = false },
                    { .name = "blacklisted", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_JAILBREAKD_LOOKUP
        {
            .handler = roothide_jailbreakd_lookup,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "port", .type = JBS_TYPE_XPC_GENERIC, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_JAILBREAKD_CHECKIN
        {
            .handler = roothide_jailbreakd_checkin,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "port", .type = JBS_TYPE_XPC_GENERIC, .out = true },
                    { 0 },
            },
        },
		// JBS_ROOTHIDE_TRUST_LIBRARY_RECURSE
		{
			.handler = roothide_trust_library_recurse,
			.args = (jbserver_arg[]){
				{ .name = "library-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "caller-library-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "caller-executable-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "current-working-dir", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_ROOTHIDE_TRUST_EXECUTABLE_RECURSE
		{
			.handler = roothide_trust_executable_recurse,
			.args = (jbserver_arg[]){
				{ .name = "executable-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "process-working-dir", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "preferred-archs", .type = JBS_TYPE_ARRAY, .out = false },
				{ 0 },
			},
		},
		//JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET
        {
            .handler = roothide_dyld_patch_enabled,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "enabled", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_DYLD_PATCH_ENABLED_SET
        {
            .handler = roothide_set_dyld_patch,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "enabled", .type = JBS_TYPE_BOOL, .out = false },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_PREPARE_USERSPACE_REBOOT
        {
            .handler = roothide_prepare_userspace_reboot,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { 0 },
            },
        },
		{ 0 },
	},
};
