#ifndef __MAIN_IN_H
#define __MAIN_IN_H

#include <graal_isolate.h>


#if defined(__cplusplus)
extern "C" {
#endif

void relay_greetPeer(graal_isolatethread_t*, int, char*, int, int);

void relay_initLedger(graal_isolatethread_t*, int, char*, int);

int relay_add(graal_isolatethread_t*, int, char*, int, int, int);

void relay_hello(graal_isolatethread_t*, int, char*, int, char*, int);

void relay_getAsset(graal_isolatethread_t*, int, char*, int, int);

void relay_transferAsset(graal_isolatethread_t*, int, char*, int, char*, int, int, int);

int relay_countMirrors(graal_isolatethread_t*, int, char*, int);

void relay_Contract(graal_isolatethread_t*, int, int);

int relay_countNulls(graal_isolatethread_t*, int, char*, int);

void relay_ledger_init(graal_isolatethread_t*, int, char*, int);

void relay_greetPerson(graal_isolatethread_t*, int, char*, int, int);

int relay_sendGreetings(graal_isolatethread_t*, int, char*, int);

int relay_getRandStringT(graal_isolatethread_t*, int, char*, int, int);

int run_main(int argc, char** argv);

void relay_sayMyName(graal_isolatethread_t*, int, char*, int, char*, int);

void relay_setBalance(graal_isolatethread_t*, int, char*, int, int);

int relay_getLedgerHash(graal_isolatethread_t*, int, char*, int);

void relay_setLedgerhash(graal_isolatethread_t*, int, char*, int, int);

void relay_stringTest(graal_isolatethread_t*, int, char*, int, char*, int, int);

int relay_getPeerId(graal_isolatethread_t*, int, char*, int);

void relay_addAssets(graal_isolatethread_t*, int, char*, int, char*, int);

void relay_sayHello(graal_isolatethread_t*, int, char*, int);

void relay_Peer(graal_isolatethread_t*, int, char*, int, int);

int relay_getName(graal_isolatethread_t*, int, char*, int);

int relay_getBalance(graal_isolatethread_t*, int, char*, int);

void mirrorCleanupIn(graal_isolatethread_t* t, int proxyHash);

void mirrorCleanupOut(graal_isolatethread_t* t, int proxyHash);

void doProxyCleanupIn(graal_isolatethread_t* t);

void vmLocatorSymbol(graal_isolatethread_t* thread);

#if defined(__cplusplus)
}
#endif
#endif
