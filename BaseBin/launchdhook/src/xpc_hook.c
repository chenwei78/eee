#include <libjailbreak/libjailbreak.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sandbox.h>
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
			roothide_trace("[launchd] observed RB2_USERREBOOT XPC; caller_pid=%d caller_euid=%d",
			               audit_token_to_pid(callerToken), audit_token_to_euid(callerToken));
			spawn_hook_note_userspace_reboot();
		}

		roothide_handle_xpc_msg(*xOut);
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
