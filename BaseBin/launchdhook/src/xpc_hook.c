#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/codesign.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>
#include <xpc_private.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sandbox.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <substrate.h>
#include <libjailbreak/jbserver.h>
#include <litehook.h>
#include "roothide_trace.h"
#include "spawn_hook.h"

mach_msg_header_t* dispatch_mach_msg_get_msg(void *message, size_t *_Nullable size_ptr);
int jbserver_received_mach_message(audit_token_t *auditToken, struct jbserver_mach_msg *jbsMachMsg);
int jbserver_received_complex_mach_message(audit_token_t *auditToken, uint64_t action, struct jbserver_mach_complex_msg *jbsMachMsg);

int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int (*xpc_receive_mach_msg_orig)(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);

#define RB2_USERREBOOT (0x2000000000000000llu)
static bool is_userspace_reboot_message(xpc_object_t message)
{
	if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
	if (xpc_dictionary_get_uint64(message, "flags") != RB2_USERREBOOT) return false;
	if (xpc_dictionary_get_uint64(message, "type") != 1) return false;
	if (!xpc_dictionary_get_value(message, "handle")) return false;
	if (xpc_dictionary_get_uint64(message, "handle") != 0) return false;
	return true;
}

static int entitlement_bool_for_token(audit_token_t *callerToken, const char *entitlement)
{
	xpc_object_t value = xpc_copy_entitlement_for_token(entitlement, callerToken);
	if (!value) return -1;

	int result = -1;
	if (xpc_get_type(value) == XPC_TYPE_BOOL) {
		result = xpc_bool_get_value(value) ? 1 : 0;
	}
	xpc_release(value);
	return result;
}

int xpc_receive_mach_msg_hook(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	size_t msgBufSize = 0;
    struct jbserver_mach_msg *jbsMachMsg = (struct jbserver_mach_msg *)dispatch_mach_msg_get_msg(msg, &msgBufSize);
	bool wasProcessed = false;
    if (jbsMachMsg != NULL && msgBufSize >= sizeof(mach_msg_header_t)) {
        size_t msgSize = jbsMachMsg->hdr.msgh_size;
        if (msgSize <= msgBufSize && msgSize >= sizeof(struct jbserver_mach_msg) && jbsMachMsg->magic == JBSERVER_MACH_MAGIC) {
			mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsMachMsg + round_msg(jbsMachMsg->hdr.msgh_size));
            jbserver_received_mach_message(&trailer->msgh_audit, jbsMachMsg);
			wasProcessed = true;
            // Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
        }
    }
	// Not needed, since we don't have any complex messages at the moment
	/*struct jbserver_mach_complex_msg *jbsComplexMachMsg = (struct jbserver_mach_complex_msg *)jbsMachMsg;
	if (!wasProcessed && jbsComplexMachMsg != NULL && msgBufSize >= sizeof(struct jbserver_mach_complex_msg)) {
		// Warning: Witchcraft incoming
		size_t msgSize = jbsComplexMachMsg->hdr.msgh_size;
		if (jbsComplexMachMsg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			uintptr_t magicOff = sizeof(struct jbserver_mach_complex_msg) + (jbsComplexMachMsg->body.msgh_descriptor_count * sizeof(mach_msg_port_descriptor_t));
			uintptr_t actionOff = magicOff + sizeof(uint64_t);
			if (msgSize >= (actionOff + sizeof(uint64_t))) {
				uint64_t magic = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + magicOff);
				if (magic == JBSERVER_MACH_MAGIC) {
					uint64_t action = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + actionOff);
					mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsComplexMachMsg + round_msg(jbsComplexMachMsg->hdr.msgh_size));
					jbserver_received_complex_mach_message(&trailer->msgh_audit, action, jbsComplexMachMsg);
					wasProcessed = true;
            		// Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
				}
			}
		}
	}*/

	int r = xpc_receive_mach_msg_orig(msg, a2, a3, a4, xOut);
	if (!wasProcessed && r == 0 && xOut && *xOut) {
		bool userspaceRebootMessage = is_userspace_reboot_message(*xOut);
		if (userspaceRebootMessage) {
			audit_token_t callerToken = {0};
			xpc_dictionary_get_audit_token(*xOut, &callerToken);
			pid_t callerPid = audit_token_to_pid(callerToken);
			char callerPath[PATH_MAX] = {0};
			int callerPathResult = proc_pidpath_audittoken(&callerToken, callerPath, sizeof(callerPath));
			uint32_t callerCSFlags = 0;
			int callerCSResult = csops_audittoken(callerPid, CS_OPS_STATUS, &callerCSFlags, sizeof(callerCSFlags), &callerToken);
			if (callerCSResult != 0) {
				callerCSResult = csops(callerPid, CS_OPS_STATUS, &callerCSFlags, sizeof(callerCSFlags));
			}
			int platformEntitlement = entitlement_bool_for_token(&callerToken, "platform-application");
			int rebootEntitlement = entitlement_bool_for_token(&callerToken, "com.apple.private.xpc.launchd.userspace-reboot");
			int watchdogEntitlement = entitlement_bool_for_token(&callerToken, "com.apple.private.iowatchdog.user-access");
			struct statfs developerStatus = {0};
			int developerStatResult = statfs("/Developer", &developerStatus);
			bool developerIsMounted = developerStatResult == 0 && strcmp(developerStatus.f_mntonname, "/Developer") == 0;
			roothide_trace("[launchd] observed RB2_USERREBOOT XPC; caller_pid=%d caller_euid=%d path_result=%d path=%s csops=%d csflags=0x%08x platform=%d platform_entitlement=%d reboot_entitlement=%d watchdog_entitlement=%d developer_statfs=%d developer_mounted=%d",
			               callerPid, audit_token_to_euid(callerToken), callerPathResult,
			               callerPath[0] ? callerPath : "(unavailable)", callerCSResult, callerCSFlags,
			               callerCSResult == 0 && (callerCSFlags & CS_PLATFORM_BINARY) != 0,
			               platformEntitlement, rebootEntitlement, watchdogEntitlement,
			               developerStatResult, developerIsMounted);
			spawn_hook_note_userspace_reboot();
		}

		if (userspaceRebootMessage) {
			if (__builtin_available(iOS 18.0, *)) {
				// RootHide 2.x carries a legacy iOS 15 workaround that force-unmounts
				// /Developer as soon as launchd receives RB2_USERREBOOT.  Its official
				// launchd XPC entry does not call that mutator, and ordinary Dopamine
				// waits until launchd's final self-replacement.  Preserve that ordering
				// on iOS 18 so launchd can complete its own authorization and teardown.
				roothide_trace("[launchd] iOS 18 RB2 path: skipped legacy RootHide pre-teardown /Developer unmount");
			}
			else {
				roothide_handle_xpc_msg(*xOut);
			}
		}
		else {
			roothide_handle_xpc_msg(*xOut);
		}
		int jbserverResult = jbserver_received_xpc_message(&gGlobalServer, *xOut);
		if (userspaceRebootMessage) {
			roothide_trace("[launchd] RB2_USERREBOOT forwarding decision; xpc_result=%d jbserver_result=%d consumed=%d",
			               r, jbserverResult, jbserverResult == 0);
		}
		if (jbserverResult == 0) {
			// Returning non null here makes launchd disregard this message
			// For jailbreak messages we have the logic to handle them
			xpc_release(*xOut);
			return 22;
		}
	}
	return r;
}

void initXPCHooks(void)
{
	xpc_receive_mach_msg_orig = xpc_receive_mach_msg;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, xpc_receive_mach_msg, xpc_receive_mach_msg_hook, NULL);
}
