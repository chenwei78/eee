#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "translation.h"
#include "trustcache.h"
#include "jbclient_xpc.h"
#include "jbclient_roothide.h"
#include "stock_fixes.h"

/* RootHide compatibility layer.  This is additive; the Dopamine 3.x
 * rootless interfaces remain the default until the RootHide runtime is
 * fully wired into the bootstrap. */
#include "roothider.h"

int jbclient_initialize_primitives_internal(bool physrwPTE);
int jbclient_initialize_primitives(void);
