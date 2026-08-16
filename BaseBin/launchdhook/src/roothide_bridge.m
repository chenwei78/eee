#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothider.h>

/*
 * Small bridge between Dopamine 3's modern launchdhook and RootHide's
 * jailbreakd lifecycle.  The iOS 18 hook implementation remains in the
 * normal launchdhook/systemhook sources; this bridge only enables the
 * RootHide-specific process service and state transitions.
 */
void roothide_launchd_preinit(void)
{
    exec_set_patch(false);
}

void roothide_launchd_postinit(bool firstLoad)
{
    launchdhookFirstLoad = firstLoad;
    exec_set_patch(true);

    // Dopamine 3's systemhook keeps the modern iOS 18 implementation and
    // normally lives in basebin.  After a userspace reboot RootHide needs a
    // stock-looking copy in /usr/lib so the existing spawn path can inject it.
    if (!firstLoad) {
        const char *systemhookPath = JBROOT_PATH("/basebin/systemhook.dylib");
        if (systemhookPath && access(systemhookPath, F_OK) == 0) {
            if (unsandbox("/usr/lib", systemhookPath) != 0) {
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
    if (initJailbreakd(firstLoad) != 0) {
        launchd_panic("RootHide jailbreakd initialization failed");
    }
}
