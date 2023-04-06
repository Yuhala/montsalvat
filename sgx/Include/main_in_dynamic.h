#ifndef __MAIN_IN_H
#define __MAIN_IN_H

#include <graal_isolate_dynamic.h>


#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*relay_greetPeer_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_initLedger_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef int (*relay_add_fn_t)(graal_isolatethread_t*, int, char*, int, int, int);

typedef void (*relay_hello_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*relay_getAsset_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_transferAsset_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int, int, int);

typedef int (*relay_countMirrors_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_Contract_fn_t)(graal_isolatethread_t*, int, int);

typedef int (*relay_countNulls_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_ledger_init_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_greetPerson_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef int (*relay_sendGreetings_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef int (*relay_getRandStringT_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef int (*run_main_fn_t)(int argc, char** argv);

typedef void (*relay_sayMyName_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*relay_setBalance_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef int (*relay_getLedgerHash_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_setLedgerhash_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_stringTest_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int, int);

typedef int (*relay_getPeerId_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_addAssets_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*relay_sayHello_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_Peer_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef int (*relay_getName_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef int (*relay_getBalance_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*mirrorCleanupIn_fn_t)(graal_isolatethread_t* t, int proxyHash);

typedef void (*mirrorCleanupOut_fn_t)(graal_isolatethread_t* t, int proxyHash);

typedef void (*doProxyCleanupIn_fn_t)(graal_isolatethread_t* t);

typedef void (*vmLocatorSymbol_fn_t)(graal_isolatethread_t* thread);

#if defined(__cplusplus)
}
#endif
#endif
