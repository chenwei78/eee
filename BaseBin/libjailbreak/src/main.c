#include "jbclient_xpc.h"
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "physrw.h"
#include "physrw_pte.h"
#include "primitives_IOSurface.h"
#include "info.h"
#include "translation.h"
#include "util.h"
#include "kcall_Fugu14.h"
#include "kcall_arm64.h"
#include <xpc/xpc.h>

static void primitive_trace(const char *format, ...)
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

	char message[700] = {0};
	va_list args;
	va_start(args, format);
	int length = vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	if (length > 0) {
		int outputLength = length < (int)sizeof(message) ? length : (int)sizeof(message) - 1;
		dprintf(trace, "[primitive] %.*s\n", outputLength, message);
		fsync(trace);
	}
	close(trace);
}

int jbclient_initialize_primitives_internal(bool physrwPTE)
{
	primitive_trace("initialization entered; uid=%d physrwPTE=%d", getuid(), physrwPTE);
	if (getuid() != 0) {
		primitive_trace("FAILURE: primitive initialization requires uid 0");
		return -1;
	}

	xpc_object_t xSystemInfo = NULL;
	primitive_trace("requesting system information from launchd");
	int systemInfoResult = jbclient_root_get_sysinfo(&xSystemInfo);
	primitive_trace("system information request returned %d object=%d", systemInfoResult, xSystemInfo != NULL);
	if (systemInfoResult == 0 && xSystemInfo) {
		SYSTEM_INFO_DESERIALIZE(xSystemInfo);
		xpc_release(xSystemInfo);
		primitive_trace("system information deserialized");
		uint64_t asidPtr = 0;
		primitive_trace("requesting %s handoff from launchd", physrwPTE ? "PTE physrw" : "full physrw");
		int handoffResult = jbclient_root_get_physrw(physrwPTE, &asidPtr);
		primitive_trace("physrw handoff returned %d asidPtr=0x%llx", handoffResult, (unsigned long long)asidPtr);
		if (handoffResult == 0) {
			int localInitResult = 0;
			if (physrwPTE) {
				localInitResult = libjailbreak_physrw_pte_init(true, asidPtr);
			}
			else {
				localInitResult = libjailbreak_physrw_init(true);
			}
			primitive_trace("local physrw initialization returned %d", localInitResult);
			if (localInitResult != 0) return -1;

			primitive_trace("initializing address translation");
			libjailbreak_translation_init();
			primitive_trace("address translation initialized; initializing IOSurface primitives");
			libjailbreak_IOSurface_primitives_init();
			primitive_trace("IOSurface primitives initialized; kalloc_local=%d", gPrimitives.kalloc_local != NULL);
			if (gPrimitives.kalloc_local) {
				if (host_is_arm64e()) {
					if (jbinfo(usesPACBypass)) {
						primitive_trace("initializing Fugu14 kcall");
						int kcallResult = jbclient_get_fugu14_kcall();
						primitive_trace("Fugu14 kcall initialization returned %d", kcallResult);
					}
				}
				else {
					primitive_trace("initializing arm64 kcall");
					int kcallResult = arm64_kcall_init();
					primitive_trace("arm64 kcall initialization returned %d", kcallResult);
				}
			}

			primitive_trace("primitive initialization complete");
			return 0;
		}
	}

	primitive_trace("FAILURE: primitive initialization could not obtain required launchd data");
	return -1;
}

int jbclient_initialize_primitives(void)
{
	return jbclient_initialize_primitives_internal(false);
}

// Used for supporting third party legacy software that still calls this function
int jbdInitPPLRW(void)
{
	return jbclient_initialize_primitives();
}
