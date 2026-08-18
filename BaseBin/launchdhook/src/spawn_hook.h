#ifndef SPAWN_HOOK_H
#define SPAWN_HOOK_H

#include <stdbool.h>

void initSpawnHooks(void);
int spawn_hook_install_result(void);
bool spawn_hook_observed_boomerang(void);
void spawn_hook_note_userspace_reboot(void);

#endif
