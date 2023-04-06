#ifndef __MAIN_OUT_H
#define __MAIN_OUT_H

#include <graal_isolate.h>


#if defined(__cplusplus)
extern "C" {
#endif

int run_main(int argc, char** argv);

void relay_doProxyOut(graal_isolatethread_t*, int, char*, int, int);

void relay_doConcreteIn(graal_isolatethread_t*, int, char*, int, char*, int);

void relay_addObjs(graal_isolatethread_t*, int, char*, int, int, int);

void relay_gcTest(graal_isolatethread_t*, int, char*, int, int, int);

void relay_Main(graal_isolatethread_t*, int);

int relay_getRandString(graal_isolatethread_t*, int, char*, int, int);

void relay_doConcreteOut(graal_isolatethread_t*, int, char*, int, char*, int);

void relay_removeObjs(graal_isolatethread_t*, int, char*, int, int, int);

void relay_doProxyIn(graal_isolatethread_t*, int, char*, int, int);

void relay_doConsistencyTest(graal_isolatethread_t*, int, char*, int, int, int);

void relay_setId(graal_isolatethread_t*, int, char*, int, int);

void relay_Person(graal_isolatethread_t*, int, char*, int);

void relay_sayMyName(graal_isolatethread_t*, int, char*, int, char*, int);

int relay_getPersonId(graal_isolatethread_t*, int, char*, int);

int relay_getName(graal_isolatethread_t*, int, char*, int);

void mirrorCleanupIn(graal_isolatethread_t* t, int proxyHash);

void mirrorCleanupOut(graal_isolatethread_t* t, int proxyHash);

void doProxyCleanupIn(graal_isolatethread_t* t);

void relay_setNamesU(graal_isolatethread_t*, int, char*, int, int);

void relay_Untrusted(graal_isolatethread_t*, int, int);

int relay_getRandStringU(graal_isolatethread_t*, int, char*, int, int);

void relay_setNameU(graal_isolatethread_t*, int, char*, int, char*, int);

void vmLocatorSymbol(graal_isolatethread_t* thread);

#if defined(__cplusplus)
}
#endif
#endif
