#include <Foundation/Foundation.h>
#include <errno.h>
#include <fcntl.h>
#include <kern_memorystatus.h>
#include <mach-o/dyld.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>

extern char **environ;

void jailbreakd_received_message(mach_port_t port);

int posix_spawnattr_setspecialport_np(posix_spawnattr_t *attr, mach_port_t new_port, int which);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

static void RootHideJailbreakdTrace(const char *format, ...)
{
	const char *tracePath = getenv("ROOTHIDE_JAILBREAKD_TRACE_PATH");
	if (!tracePath || !tracePath[0] || !format) return;

	int trace = open(tracePath, O_WRONLY | O_APPEND);
	if (trace < 0) return;

	struct stat traceStatus = {0};
	if (fstat(trace, &traceStatus) != 0 || traceStatus.st_size >= 256 * 1024) {
		close(trace);
		return;
	}

	char message[900] = {0};
	va_list args;
	va_start(args, format);
	int length = vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	if (length > 0) {
		dprintf(trace, "[jailbreakd] %.*s\n", (int)MIN((size_t)length, sizeof(message) - 1), message);
		fsync(trace);
	}
	close(trace);
}

int setJetsamLimit(uint32_t sizeInMB, bool is_fatal_limit)
{
	uint32_t cmd = is_fatal_limit ? MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT : MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK;
	int rc = memorystatus_control(cmd, getpid(), sizeInMB, NULL, 0);
	if (rc < 0) perror("memorystatus_control");
	return rc;
}

void enableXPCLog(void* debugLog, void* errorLog);

int main(int argc, char* argv[])
{
	RootHideJailbreakdTrace("main entered; uid=%d pid=%d ppid=%d", getuid(), getpid(), getppid());
	bool firstLiveInjection = getenv("ROOTHIDE_JAILBREAKD_FIRST_LOAD") != NULL;
	unsetenv("ROOTHIDE_JAILBREAKD_FIRST_LOAD");

	// crashreporter_start installs task exception ports.  iOS 18 kills this
	// daemon at that call even after the first-load process patch has been
	// applied.  It is diagnostic-only and must not sit on the service's critical
	// startup path, including after the userspace reboot.
	RootHideJailbreakdTrace("phase skipped: crash reporter disabled for jailbreakd");

	if (firstLiveInjection) {
		// The first instance only exists to patch Bootstrap children before the
		// imminent userspace reboot.  Do not make it depend on optional Jetsam
		// policy changes while launchd is in the live-injection state.
		RootHideJailbreakdTrace("phase skipped: jetsam limit during first live injection");
	}
	else {
		errno = 0;
		int jetsamResult = setJetsamLimit(50, false);
		RootHideJailbreakdTrace("jetsam limit request returned %d errno=%d; continuing even if unavailable", jetsamResult, errno);
	}

#ifdef ENABLE_LOGS
	enableXPCLog(JBLogDebugFunction, JBLogErrorFunction);
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif

	JBLogDebug("Hello from jailbrakd! uid=%d pid=%d ppid=%d", getuid(), getpid(), getppid());

	@autoreleasepool {

		RootHideJailbreakdTrace("phase: reading registered ports");
		mach_port_t *registeredPorts=NULL;
		mach_msg_type_number_t registeredPortsCount = 0;
		kern_return_t kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
		if(kr != KERN_SUCCESS || registeredPortsCount < 3) {
			JBLogError("mach_ports_lookup error: %d, %x, %s", registeredPortsCount, kr, mach_error_string(kr));
			RootHideJailbreakdTrace("FAILURE: mach_ports_lookup count=%d kr=%x", registeredPortsCount, kr);
			return 1;
		}
		for(int i=0; i<registeredPortsCount; i++) {
			JBLogDebug("registeredPorts[%d]: %x", i, registeredPorts[i]);
		}

		mach_port_t bootstraport = registeredPorts[2];
		if(!MACH_PORT_VALID(bootstraport)) {
			JBLogError("invalid bootstraport");
			RootHideJailbreakdTrace("FAILURE: registered bootstrap port is invalid");
			return 2;
		}
		JBLogDebug("bootstraport: %x", bootstraport);
		RootHideJailbreakdTrace("phase complete: registered bootstrap port=%x", bootstraport);

		registeredPorts[2] = MACH_PORT_NULL;
		kr = mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);
		if (kr != KERN_SUCCESS) {
			RootHideJailbreakdTrace("FAILURE: clearing registered bootstrap port returned %x", kr);
			return 7;
		}

		JBLogDebug("start initializing jb primitives");
		RootHideJailbreakdTrace("phase: initializing jailbreak primitives");
		jbclient_xpc_set_custom_port(bootstraport);
		int ret = jbclient_initialize_primitives();
		JBLogDebug("jbclient_initialize_primitives ret: %d", ret);
		RootHideJailbreakdTrace("jailbreak primitive initialization returned %d", ret);
		if(ret != 0) {
			JBLogError("Failed to initialize jailbreak primitives: %d", ret);
			RootHideJailbreakdTrace("FAILURE: jailbreak primitive initialization returned %d", ret);
			return 3;
		}

		if(getenv("RESPAWN_REQUIRED"))
		{
			RootHideJailbreakdTrace("phase: preparing post-reboot jailbreakd respawn");
			unsetenv("RESPAWN_REQUIRED");

			char selfPath[PATH_MAX]={0};
			uint32_t selfPathSize = sizeof(selfPath);
			_NSGetExecutablePath(selfPath, &selfPathSize);
	
			pid_t pid;
			posix_spawnattr_t attr = NULL;
			posix_spawnattr_init(&attr);
			posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
			// posix_spawnattr_setspecialport_np(&attr, bootstraport, TASK_BOOTSTRAP_PORT);
			// posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ bootstraport, MACH_PORT_NULL }, 3);
			posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, bootstraport }, 3);
			int ret = posix_spawn(&pid, selfPath, NULL, &attr, argv, environ);
			posix_spawnattr_destroy(&attr);

			if(ret != 0) {
				JBLogError("posix_spawn jailbreakd failed: %d, %s", ret, strerror(ret));
				RootHideJailbreakdTrace("FAILURE: post-reboot respawn returned %d errno=%d", ret, errno);
				return 4;
			}

			JBLogDebug("jailbreakd respawned: %d", pid);
			RootHideJailbreakdTrace("post-reboot jailbreakd spawned suspended; pid=%d", pid);
	
			int patchResult = unrestrict(pid, proc_patch_dyld, false);
			if(patchResult != 0) {
				JBLogError("Failed to unrestrict process %d", pid);
				RootHideJailbreakdTrace("FAILURE: patching post-reboot jailbreakd returned %d", patchResult);
				kill(pid, SIGKILL);
				waitpid(pid, NULL, 0);
				return 5;
			}
			RootHideJailbreakdTrace("phase complete: post-reboot jailbreakd process patch");

			if(dyld_patch_enabled()) {
				RootHideJailbreakdTrace("dyld patch enabled; handing service role to respawned jailbreakd");
				kill(pid, SIGCONT);
				return 0;
			} else {
				RootHideJailbreakdTrace("dyld patch disabled; keeping original jailbreakd instance");
				kill(pid, SIGKILL);
				waitpid(pid, NULL, 0);
			}
		}

		JBLogDebug("check in jailbreakd port...");
		RootHideJailbreakdTrace("phase: checking in with launchd");
		mach_port_t serverPort = jbclient_jailbreakd_checkin();
		if (!MACH_PORT_VALID(serverPort)) {
			JBLogError("Failed to check in server port");
			RootHideJailbreakdTrace("FAILURE: launchd check-in returned an invalid server port");
			return 6;
		}

		JBLogDebug("starting jailbreakd server, port=%x", serverPort);
		RootHideJailbreakdTrace("phase complete: check-in succeeded; server port=%x", serverPort);

		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_main_queue());
		if (!source) {
			RootHideJailbreakdTrace("FAILURE: creating jailbreakd server dispatch source");
			return 7;
		}
		dispatch_source_set_event_handler(source, ^{
			jailbreakd_received_message(serverPort);
		});
		dispatch_resume(source);

		dispatch_main();
	}

	JBLogDebug("jailbreakd exit...");
	return 0;
}
