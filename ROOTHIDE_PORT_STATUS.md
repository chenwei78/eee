# Dopamine 3.x -> RootHide port status

## Baselines

- Upstream source: `Dopamine-3.x`
- RootHide reference: `Dopamine2-roothide-2.x`
- Target profile: iPhone 11 (A13), iOS 18.0.1

## Confirmed reusable pieces

- Dopamine 3.x contains the current A12/A13 exploit selection and iOS 18 kernel-offset handling.
- Dopamine 3.x contains the newer `libjailbreak`, `dyldhook`, `launchdhook`, `systemhook`, and bootstrap flow.
- RootHide 2.x contains the RootHide-specific process, dyld, blacklist, jailbreakd, and bootstrap adaptations.

## High-risk incompatibilities

- RootHide 2.x replaces the `BaseBin` component graph with `jailbreakd`, `bootstrapper`, and `roothidehooks`; Dopamine 3.x uses `hookd`, `dopamine`, and `rootlesshooks`.
- RootHide 2.x's `info.h` layout omits newer SPTM/TXM/iOS 18 fields present in Dopamine 3.x. It must not be copied over the modern layout.
- RootHide 2.x's `dyldhook` build targets pre-iOS-18 generated code; its iOS 18 support cannot be restored by copying that directory wholesale.
- RootHide-specific code depends on additional kernel offsets and XPC domains that must be added compatibly to the 3.x interfaces.

## Porting rule

Preserve the Dopamine 3.x exploit and modern offset code. Port RootHide behavior as additive compatibility layers, then validate each layer with a macOS/Xcode build and a clean device boot.

## Current state

The first additive layer is now imported:

- RootHide process/dyld helper sources are present under `BaseBin/libjailbreak/src/roothider`.
- RootHide client APIs and the RootHide XPC domain are registered without replacing Dopamine's existing domains.
- `system_info` has additive RootHide state/symbol fields and serialization entries.
- The original `Dopamine-3.x` and `Dopamine2-roothide-2.x` trees remain unchanged.

The quoted-include preflight for the imported layer passes.

## Runtime wiring completed in this pass

- RootHide bootstrap lifecycle is additive in `DOBootstrapper.m`: it creates and discovers `.jbroot-<jbrand>`, uses the AppGroup secondary root for writable `/var`, extracts the bundled 1900 bootstrap, installs `basebin.tar`, and installs `roothideapp.deb` during finalization.
- `DOEnvironmentManager` now has RootHide root discovery/state methods in the port copy, while the original Dopamine 3 environment implementation remains present for comparison.
- Dopamine 3 patchfinding now requests optional RootHide `namecache` and `amfi_oids` sets, and the privilege stage sets `CS_INSTALLER` and rejects an already-active competing jailbreak.
- BaseBin trustcache loading uses RootHide randomized cdhashes; dyld fakelib generation and dyld trustcache upload run after launchdhook injection.
- The RootHide XPC domain is registered, `jailbreakd` is initialized from launchdhook, and systemhook prefers `roothidehooks.dylib` for SpringBoard, lsd, and cfprefsd.
- The app bundle identifier/preferences were changed to the RootHide variant, and `roothideapp.deb` was added to the Xcode resource phase.

## Remaining validation blockers

- The Windows workspace cannot run the required macOS/Xcode/iPhoneOS toolchain. The checked-out `BaseBin/ChOma` and `BaseBin/XPF` directories are also empty submodule placeholders here, so no meaningful arm64e link can be produced in this environment.
- The actual iOS 18.0.1 `namecache`/`amfi_oids` dictionaries must be confirmed in the current XPF submodule, then the complete BaseBin must be built on macOS and tested on a clean iPhone 11. If either optional set is unavailable, the RootHide unsandbox/dyld path is not ready for device use.
- The port has not yet been run through a clean-device jailbreak, userspace reboot, process injection, and recovery cycle; it must not be treated as an installable jailbreak package until that validation succeeds.
