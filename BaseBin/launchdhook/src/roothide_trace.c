#include "roothide_trace.h"

#include <libjailbreak/libjailbreak.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char gRootHideTracePath[PATH_MAX];

void roothide_trace_init(void)
{
    gRootHideTracePath[0] = '\0';

    int config = open(JBROOT_PATH("/basebin/.roothide_trace_path"), O_RDONLY);
    if (config < 0) return;

    ssize_t count = read(config, gRootHideTracePath, sizeof(gRootHideTracePath) - 1);
    close(config);
    if (count > 0) {
        gRootHideTracePath[count] = '\0';
        gRootHideTracePath[strcspn(gRootHideTracePath, "\r\n")] = '\0';
    }
    else {
        gRootHideTracePath[0] = '\0';
    }

    roothide_trace("[launchd] trace channel connected");
}

void roothide_trace(const char *format, ...)
{
    if (!gRootHideTracePath[0] || !format) return;

    int trace = open(gRootHideTracePath, O_WRONLY | O_APPEND);
    if (trace < 0) return;

    char line[1024];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(line, sizeof(line), format, args);
    va_end(args);

    if (length > 0) {
        size_t bytesToWrite = (size_t)length;
        if (bytesToWrite >= sizeof(line)) bytesToWrite = sizeof(line) - 1;
        write(trace, line, bytesToWrite);
        write(trace, "\n", 1);
        fsync(trace);
    }
    close(trace);
}
