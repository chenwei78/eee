#include <spawn.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver.h>
#include <libjailbreak/jbserver_boomerang.h>
#include <libjailbreak/physrw.h>
#include <libjailbreak/physrw_pte.h>
#include <libjailbreak/primitives_IOSurface.h>
#include <libjailbreak/kcall_Fugu14.h>
#include <libjailbreak/kcall_arm64.h>
#include <libjailbreak/stock_fixes.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include "roothide_trace.h"

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *__restrict attr, mach_port_t portarray[], uint32_t count);

#define JB_DOMAIN_PRIMITIVE_STORAGE 10

#define JB_PRIMITIVE_STORAGE_RETRIEVE_PHYSRW 1
#define JB_PRIMITIVE_STORAGE_RETRIEVE_KCALL 2

static pthread_mutex_t gBoomerangStashLock = PTHREAD_MUTEX_INITIALIZER;

static int boomerang_stashPrimitivesOnce(void)
{
	roothide_trace("[boomerang] phase: stashing primitives for userspace reboot");
	dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);

	mach_port_t serverPort = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	if (kr != KERN_SUCCESS) {
		roothide_trace("[boomerang] FAILURE: allocating userspace-reboot handoff port returned %d", kr);
		return -1;
	}
	kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr != KERN_SUCCESS) {
		roothide_trace("[boomerang] FAILURE: inserting userspace-reboot handoff port right returned %d", kr);
		mach_port_destroy(mach_task_self(), serverPort);
		return -2;
	}

	// Small server provided to boomerang to obtain exploit primitives
	dispatch_source_t serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
	if (!serverSource) {
		roothide_trace("[boomerang] FAILURE: creating userspace-reboot handoff source");
		mach_port_destroy(mach_task_self(), serverPort);
		return -3;
	}
	dispatch_source_set_event_handler(serverSource, ^{
		xpc_object_t xdict = NULL;
		if (!xpc_pipe_receive(serverPort, &xdict)) {
			if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
				dispatch_semaphore_signal(boomerangDone);
			}
			if (xdict) xpc_release(xdict);
		}
	});
	dispatch_resume(serverSource);

	// Spawn boomerang process
	pid_t boomerangPid = 0;
	posix_spawnattr_t attr = NULL;
	int ret = posix_spawnattr_init(&attr);
	bool attrInitialized = ret == 0;
	if (ret == 0) ret = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, serverPort }, 3);
	if (ret == 0) {
		const char *boomerangPath = JBROOT_PATH("/basebin/boomerang");
		ret = posix_spawn(&boomerangPid, boomerangPath, NULL, &attr, (char *const[]){ (char *)boomerangPath, NULL }, NULL);
	}
	if (attrInitialized) posix_spawnattr_destroy(&attr);
	if (ret != 0) {
		roothide_trace("[boomerang] FAILURE: spawning userspace-reboot handoff process returned %d", ret);
		dispatch_source_cancel(serverSource);
		mach_port_destroy(mach_task_self(), serverPort);
		return ret;
	}
	roothide_trace("[boomerang] userspace-reboot handoff process spawned; pid=%d", boomerangPid);

	// Wait for boomerang to retrieve the primitives from launchd.  Monitor the
	// child at the same time so an early exit or a broken message path cannot
	// freeze PID 1 forever during the userspace reboot.
	bool handoffComplete = false;
	for (int attempt = 1; attempt <= 400; attempt++) {
		if (dispatch_semaphore_wait(boomerangDone, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 20)) == 0) {
			handoffComplete = true;
			break;
		}

		int childStatus = 0;
		pid_t waitResult = waitpid(boomerangPid, &childStatus, WNOHANG);
		if (waitResult == boomerangPid) {
			if (WIFEXITED(childStatus)) {
				roothide_trace("[boomerang] FAILURE: handoff process exited with code %d", WEXITSTATUS(childStatus));
			}
			else if (WIFSIGNALED(childStatus)) {
				roothide_trace("[boomerang] FAILURE: handoff process terminated by signal %d", WTERMSIG(childStatus));
			}
			dispatch_source_cancel(serverSource);
			mach_port_destroy(mach_task_self(), serverPort);
			return -4;
		}
		if (waitResult < 0 && errno != EINTR) {
			roothide_trace("[boomerang] FAILURE: monitoring handoff process returned errno=%d", errno);
			kill(boomerangPid, SIGKILL);
			while (waitpid(boomerangPid, NULL, 0) < 0 && errno == EINTR) {}
			dispatch_source_cancel(serverSource);
			mach_port_destroy(mach_task_self(), serverPort);
			return -6;
		}
	}

	if (!handoffComplete) {
		roothide_trace("[boomerang] FAILURE: timed out stashing primitives after 20 seconds");
		kill(boomerangPid, SIGKILL);
		while (waitpid(boomerangPid, NULL, 0) < 0 && errno == EINTR) {}
		dispatch_source_cancel(serverSource);
		mach_port_destroy(mach_task_self(), serverPort);
		return -5;
	}

	roothide_trace("[boomerang] handoff process received primitives");
	dispatch_source_cancel(serverSource);
	mach_port_destroy(mach_task_self(), serverPort);

	// Stash boomerang pid in environment to later be able to call waitpid on it
	char pidBuf[10];
	snprintf(pidBuf, 10, "%d", boomerangPid);
	setenv("BOOMERANG_PID", pidBuf, 1);
	roothide_trace("[boomerang] phase complete: primitives stashed for userspace reboot");
	return 0;
}

int boomerang_stashPrimitives(void)
{
	pthread_mutex_lock(&gBoomerangStashLock);

	const char *existingPidString = getenv("BOOMERANG_PID");
	if (existingPidString && existingPidString[0]) {
		char *end = NULL;
		errno = 0;
		long existingPid = strtol(existingPidString, &end, 10);
		bool validPid = errno == 0 && end && end[0] == '\0' && existingPid > 1 && existingPid <= INT_MAX;
		if (validPid && (kill((pid_t)existingPid, 0) == 0 || errno == EPERM)) {
			roothide_trace("[boomerang] primitives already stashed in live handoff process; pid=%ld", existingPid);
			pthread_mutex_unlock(&gBoomerangStashLock);
			return 0;
		}

		roothide_trace("[boomerang] stale handoff state found; pid=%s, creating a replacement", existingPidString);
		unsetenv("BOOMERANG_PID");
	}

	int result = boomerang_stashPrimitivesOnce();
	pthread_mutex_unlock(&gBoomerangStashLock);
	return result;
}

int boomerang_recoverPrimitives(bool firstRetrieval, bool shouldEndBoomerang)
{
	// Mach port to boomerang should be stored in our registeredPorts[2]
	// Use it to recover primitives, afterwards replace it with MACH_PORT_NULL to make launchd happy
	mach_port_t *registeredPorts;
	mach_msg_type_number_t registeredPortsCount = 0;
	if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 || registeredPortsCount < 3) {
		roothide_trace("[boomerang] FAILURE: launchd has no registered primitive port");
		return -1;
	}
	mach_port_t boomerangPort = registeredPorts[2];
	if (!MACH_PORT_VALID(boomerangPort)) {
		roothide_trace("[boomerang] FAILURE: registered primitive port is null");
		return -2;
	}
	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
	kern_return_t registerResult = mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);
	if (registerResult != KERN_SUCCESS) {
		roothide_trace("[boomerang] FAILURE: clearing registered primitive port returned %d", registerResult);
		return -4;
	}

	// Recover boomerang pid from environment
	pid_t boomerangPid = 0;
	const char *pidBuf = getenv("BOOMERANG_PID");
	if (pidBuf) {
		boomerangPid = atoi(pidBuf);
		unsetenv("BOOMERANG_PID");
	}

	// Retrieve primitives
	// For performance reasons we only use physrw_pte until the first userspace reboot
	// Handing off full physrw from the app is really slow and causes watchdog timeouts
	// But from launchd it's generally fine, no clue why
	bool physrwPTE = firstRetrieval && !is_kcall_available();
	roothide_trace("[boomerang] initializing primitives; physrwPTE=%d", physrwPTE);
	int primitiveResult = jbclient_initialize_primitives_internal(physrwPTE);
	roothide_trace("[boomerang] primitive initialization returned %d", primitiveResult);

	int doneResult = 0;
	if (shouldEndBoomerang) {
		// Send done message to boomerang
		roothide_trace("[boomerang] notifying Dopamine that primitive handoff is complete");
		doneResult = -1;
		for (int attempt = 1; attempt <= 20; attempt++) {
			doneResult = jbclient_boomerang_done();
			if (doneResult == 0) break;
			usleep(50000);
		}
		roothide_trace("[boomerang] primitive handoff notification returned %d", doneResult);

		// Remove the handoff process without allowing a failed done message to
		// turn into an unbounded wait in launchd's constructor.
		if (boomerangPid != 0) {
			if (doneResult != 0) kill(boomerangPid, SIGKILL);
			bool reaped = false;
			for (int attempt = 1; attempt <= 100; attempt++) {
				int boomerangStatus = 0;
				pid_t waitResult = waitpid(boomerangPid, &boomerangStatus, WNOHANG);
				if (waitResult == boomerangPid || (waitResult < 0 && errno == ECHILD)) {
					reaped = true;
					break;
				}
				usleep(50000);
			}
			if (!reaped) {
				roothide_trace("[boomerang] FAILURE: handoff process did not exit after completion");
				kill(boomerangPid, SIGKILL);
				while (waitpid(boomerangPid, NULL, 0) < 0 && errno == EINTR) {}
				if (doneResult == 0) doneResult = -2;
			}
		}
	}

	if (primitiveResult != 0) return primitiveResult;
	if (doneResult != 0) return -3;
	return 0;
}
