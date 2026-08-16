#ifndef DOPAMINE_ROOTHIDE_PATHS_H
#define DOPAMINE_ROOTHIDE_PATHS_H

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <libjailbreak/jbroot.h>
#include <libjailbreak/jbclient_xpc.h>

static inline const char *roothide_current_root(void)
{
    const char *root = get_jbroot();
    if (!root || !root[0]) root = jbclient_get_jbroot();
    return root;
}

static inline const char *jbroot(const char *path)
{
    static __thread char buffer[PATH_MAX];
    const char *root = roothide_current_root();
    if (!path || !root) return path;
    if (!strncmp(path, root, strlen(root))) return path;
    strlcpy(buffer, root, sizeof(buffer));
    if (path[0] != '/') strlcat(buffer, "/", sizeof(buffer));
    strlcat(buffer, path, sizeof(buffer));
    return buffer;
}

static inline const char *rootfs(const char *path)
{
    static __thread char buffer[PATH_MAX];
    const char *root = roothide_current_root();
    if (!path || !root) return path;
    size_t rootLength = strlen(root);
    if (!strncmp(path, root, rootLength)) {
        strlcpy(buffer, "/rootfs", sizeof(buffer));
        strlcat(buffer, path + rootLength, sizeof(buffer));
        return buffer;
    }
    strlcpy(buffer, "/rootfs", sizeof(buffer));
    if (path[0] != '/') strlcat(buffer, "/", sizeof(buffer));
    strlcat(buffer, path, sizeof(buffer));
    return buffer;
}

#endif
