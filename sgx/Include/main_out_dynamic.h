#ifndef __MAIN_OUT_H
#define __MAIN_OUT_H

#include <graal_isolate_dynamic.h>


#if defined(__cplusplus)
extern "C" {
#endif

typedef int (*run_main_fn_t)(int argc, char** argv);

typedef void (*relay_doProxyOut_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_doConcreteIn_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*relay_addObjs_fn_t)(graal_isolatethread_t*, int, char*, int, int, int);

typedef void (*relay_gcTest_fn_t)(graal_isolatethread_t*, int, char*, int, int, int);

typedef void (*relay_Main_fn_t)(graal_isolatethread_t*, int);

typedef int (*relay_getRandString_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_doConcreteOut_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*relay_removeObjs_fn_t)(graal_isolatethread_t*, int, char*, int, int, int);

typedef void (*relay_doProxyIn_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_doConsistencyTest_fn_t)(graal_isolatethread_t*, int, char*, int, int, int);

typedef void (*relay_setId_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_Person_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*relay_sayMyName_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef int (*relay_getPersonId_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef int (*relay_getName_fn_t)(graal_isolatethread_t*, int, char*, int);

typedef void (*mirrorCleanupIn_fn_t)(graal_isolatethread_t* t, int proxyHash);

typedef void (*mirrorCleanupOut_fn_t)(graal_isolatethread_t* t, int proxyHash);

typedef void (*doProxyCleanupIn_fn_t)(graal_isolatethread_t* t);

typedef void (*relay_setNamesU_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_Untrusted_fn_t)(graal_isolatethread_t*, int, int);

typedef int (*relay_getRandStringU_fn_t)(graal_isolatethread_t*, int, char*, int, int);

typedef void (*relay_setNameU_fn_t)(graal_isolatethread_t*, int, char*, int, char*, int);

typedef void (*vmLocatorSymbol_fn_t)(graal_isolatethread_t* thread);

#if defined(__cplusplus)
}
#endif
#endif
