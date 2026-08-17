#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothider.h>
#import "roothide_trace.h"
#import "jbserver/jbserver_global.h"

/*
 * Small bridge between Dopamine 3's modern launchdhook and RootHide's
 * jailbreakd lifecycle.  The iOS 18 hook implementation remains in the
 * normal launchdhook/systemhook sources; this bridge only enables the
 * RootHide-specific process service and state transitions.
 */
static int roothide_jailbreakd_bootstrap_message_handler(xpc_object_t message)
{
    uint64_t domain = xpc_dictionary_get_uint64(message, "jb-domain");
    uint64_t action = xpc_dictionary_get_uint64(message, "action");
    roothide_trace("[launchd] direct jailbreakd bootstrap message; domain=%llu action=%llu",
                   (unsigned long long)domain, (unsigned long long)action);
    int result = jbserver_received_xpc_message(&gGlobalServer, message);
    roothide_trace("[launchd] direct jailbreakd bootstrap handler returned %d", result);
    return result;
}

void roothide_launchd_preinit(void)
{
    jailbreakdSetBootstrapMessageHandler(roothide_jailbreakd_bootstrap_message_handler);
    exec_set_patch(false);
}

void roothide_launchd_postinit(bool firstLoad)
{
    launchdhookFirstLoad = firstLoad;

    roothide_trace("[roothide] post-initialization entered; firstLoad=%d", firstLoad);

    // On the first load launchdhook is entered through opainject's ROP
    // thread while the other launchd threads are suspended.  Starting the
    // RootHide service here can block posix_spawn during dlopen and trigger
    // a userspace restart.  Dopamine will perform a userspace reboot after
    // it has generated the RootHide environment; initialize then instead.
    if (firstLoad) {
        roothide_trace("[roothide] deferred until the userspace reboot; this is expected on first injection");
        return;
    }

    exec_set_patch(true);

    // Dopamine 3's systemhook keeps the modern iOS 18 implementation and
    // normally lives in basebin.  After a userspace reboot RootHide needs a
    // stock-looking copy in /usr/lib so the existing spawn path can inject it.
    if (!firstLoad) {
        const char *systemhookPath = JBROOT_PATH("/basebin/systemhook.dylib");
        if (systemhookPath && access(systemhookPath, F_OK) == 0) {
            if (unsandbox("/usr/lib", systemhookPath) != 0) {
                roothide_trace("[roothide] FAILURE: could not install systemhook in /usr/lib");
                launchd_panic("RootHide systemhook installation failed");
                return;
            }
        }
    }

    if (@available(iOS 16.0, *)) {
        if (ksymbol(developer_mode_status) && ksymbol(launch_env_logging)) {
            hideDeveloperMode();
        }
    }

    loadAppStoredIdentifiers();
    int jailbreakdResult = initJailbreakd(firstLoad);
    if (jailbreakdResult != 0) {
        roothide_trace("[roothide] FAILURE: jailbreakd initialization returned %d", jailbreakdResult);
        launchd_panic("RootHide jailbreakd initialization failed");
    }
    else {
        roothide_trace("[roothide] phase complete: jailbreakd initialization");
    }
}
