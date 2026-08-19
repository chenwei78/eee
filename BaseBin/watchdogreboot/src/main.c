#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <notify.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libjailbreak/watchdog_reboot.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)

static char gRootHideWatchdogTracePath[PATH_MAX];
static int gRootHideWatchdogRebootToken = -1;
static int gRootHideWatchdogPingToken = -1;
static int gRootHideWatchdogResultToken = -1;
static bool gRootHideWatchdogRebootInFlight = false;

static void RootHideWatchdogTraceInit(void)
{
	gRootHideWatchdogTracePath[0] = '\0';

	Dl_info imageInfo = {0};
	if (!dladdr((const void *)&RootHideWatchdogTraceInit, &imageInfo) || !imageInfo.dli_fname) return;

	const char *lastSlash = strrchr(imageInfo.dli_fname, '/');
	if (!lastSlash) return;

	size_t directoryLength = (size_t)(lastSlash - imageInfo.dli_fname);
	static const char configName[] = "/.roothide_trace_path";
	if (directoryLength + sizeof(configName) > PATH_MAX) return;

	char configPath[PATH_MAX] = {0};
	memcpy(configPath, imageInfo.dli_fname, directoryLength);
	memcpy(configPath + directoryLength, configName, sizeof(configName));

	int config = open(configPath, O_RDONLY);
	if (config < 0) return;

	ssize_t count = read(config, gRootHideWatchdogTracePath, sizeof(gRootHideWatchdogTracePath) - 1);
	close(config);
	if (count <= 0) {
		gRootHideWatchdogTracePath[0] = '\0';
		return;
	}

	gRootHideWatchdogTracePath[count] = '\0';
	gRootHideWatchdogTracePath[strcspn(gRootHideWatchdogTracePath, "\r\n")] = '\0';
}

static void RootHideWatchdogTrace(const char *format, ...)
{
	if (!gRootHideWatchdogTracePath[0] || !format) return;

	int trace = open(gRootHideWatchdogTracePath, O_WRONLY | O_APPEND);
	if (trace < 0) return;

	struct stat traceStatus = {0};
	if (fstat(trace, &traceStatus) != 0 || traceStatus.st_size >= 256 * 1024) {
		close(trace);
		return;
	}

	char message[900] = {0};
	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	dprintf(trace, "[watchdogd] %s\n", message);
	fsync(trace);
	close(trace);
}

static void RootHideWatchdogHandlePing(void)
{
	uint32_t readyResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_READY_NOTIFICATION);
	RootHideWatchdogTrace("userspace-reboot readiness probe received; ready_result=%u", readyResult);
}

static void RootHideWatchdogHandleReboot(void)
{
	bool expected = false;
	if (!__atomic_compare_exchange_n(&gRootHideWatchdogRebootInFlight, &expected, true,
	                                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		RootHideWatchdogTrace("duplicate userspace-reboot request ignored");
		return;
	}

	uint32_t receivedResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_RECEIVED_NOTIFICATION);
	RootHideWatchdogTrace("userspace-reboot request received; pid=%d uid=%d euid=%d received_result=%u",
	                      getpid(), getuid(), geteuid(), receivedResult);
	RootHideWatchdogTrace("calling reboot3 with RB2_USERREBOOT");
	errno = 0;
	int result = reboot3(RB2_USERREBOOT);
	int savedErrno = errno;
	uint64_t resultState = ((uint64_t)(uint32_t)result << 32) | (uint32_t)savedErrno;
	uint32_t stateResult = notify_set_state(gRootHideWatchdogResultToken, resultState);
	uint32_t resultPostResult = UINT32_MAX;
	if (stateResult == NOTIFY_STATUS_OK) {
		resultPostResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_RESULT_NOTIFICATION);
	}
	if (result == 0) {
		RootHideWatchdogTrace("reboot3 returned 0 errno=%d (%s); state_result=%u post_result=%u",
		                      savedErrno, strerror(savedErrno), stateResult, resultPostResult);
	}
	else {
		RootHideWatchdogTrace("FAILURE: reboot3 returned %d errno=%d (%s); state_result=%u post_result=%u",
		                      result, savedErrno, strerror(savedErrno), stateResult, resultPostResult);
	}
	__atomic_store_n(&gRootHideWatchdogRebootInFlight, false, __ATOMIC_RELEASE);
}

__attribute__((constructor)) static void initializer(void)
{
	RootHideWatchdogTraceInit();

	uint32_t rebootNotifyResult = notify_register_dispatch(
		ROOTHIDE_WATCHDOG_REBOOT_NOTIFICATION,
		&gRootHideWatchdogRebootToken,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0),
		^(int token) {
			(void)token;
			RootHideWatchdogHandleReboot();
		});
	uint32_t pingNotifyResult = notify_register_dispatch(
		ROOTHIDE_WATCHDOG_REBOOT_PING_NOTIFICATION,
		&gRootHideWatchdogPingToken,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0),
		^(int token) {
			(void)token;
			RootHideWatchdogHandlePing();
		});
	uint32_t resultNotifyResult = notify_register_check(
		ROOTHIDE_WATCHDOG_REBOOT_RESULT_NOTIFICATION,
		&gRootHideWatchdogResultToken);

	uint32_t readyResult = UINT32_MAX;
	if (rebootNotifyResult == NOTIFY_STATUS_OK &&
	    pingNotifyResult == NOTIFY_STATUS_OK &&
	    resultNotifyResult == NOTIFY_STATUS_OK) {
		readyResult = notify_post(ROOTHIDE_WATCHDOG_REBOOT_READY_NOTIFICATION);
	}
	if (rebootNotifyResult == NOTIFY_STATUS_OK &&
	    pingNotifyResult == NOTIFY_STATUS_OK &&
	    resultNotifyResult == NOTIFY_STATUS_OK &&
	    readyResult == NOTIFY_STATUS_OK) {
		RootHideWatchdogTrace("userspace-reboot notification channel ready; notify_result=%u ping_result=%u result_result=%u ready_result=%u",
		                      rebootNotifyResult, pingNotifyResult, resultNotifyResult, readyResult);
	}
	else {
		RootHideWatchdogTrace("FAILURE: userspace-reboot notification setup returned notify=%u ping=%u result=%u ready=%u",
		                      rebootNotifyResult, pingNotifyResult, resultNotifyResult, readyResult);
	}
}
