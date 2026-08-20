#ifndef SPAWN_HOOK_H
#define SPAWN_HOOK_H

#include <stdbool.h>

void initSpawnHooks(bool deferSystemChildPatching);
int spawn_hook_install_result(void);
int exec_hook_ensure_installed(void);
void spawn_hook_note_userspace_reboot(void);

#endif
