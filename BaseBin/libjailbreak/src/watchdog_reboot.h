#ifndef ROOTHIDE_WATCHDOG_REBOOT_H
#define ROOTHIDE_WATCHDOG_REBOOT_H

// Keep these names versioned so a stale reboot bridge from an older live
// injection cannot accidentally consume a request from a newer protocol.
#define ROOTHIDE_WATCHDOG_REBOOT_NOTIFICATION \
	"com.opa334.Dopamine.roothide.userspace-reboot.v1"
#define ROOTHIDE_WATCHDOG_REBOOT_PING_NOTIFICATION \
	"com.opa334.Dopamine.roothide.userspace-reboot.ping.v1"
#define ROOTHIDE_WATCHDOG_REBOOT_READY_NOTIFICATION \
	"com.opa334.Dopamine.roothide.userspace-reboot.ready.v1"
#define ROOTHIDE_WATCHDOG_REBOOT_RECEIVED_NOTIFICATION \
	"com.opa334.Dopamine.roothide.userspace-reboot.received.v1"
#define ROOTHIDE_WATCHDOG_REBOOT_RESULT_NOTIFICATION \
	"com.opa334.Dopamine.roothide.userspace-reboot.result.v1"

#endif
