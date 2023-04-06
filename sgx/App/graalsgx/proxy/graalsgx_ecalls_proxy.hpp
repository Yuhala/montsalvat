/* Generated by GraalVM SGXProxyGenerator. */ 

#if defined(__cplusplus)
extern "C" {
#endif

void ecall_relay_Contract(graal_isolatethread_t* param_0, int param_1, int param_2)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_Contract(global_eid, NULL, param_1, param_2);

}

int ecall_relay_add(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4, int param_5)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_add(global_eid, &ret,NULL, param_1, param_2, param_3, param_4, param_5);

return ret;
}

int ecall_relay_countMirrors(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_countMirrors(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

int ecall_relay_countNulls(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_countNulls(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

void ecall_relay_getAsset(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_getAsset(global_eid, NULL, param_1, param_2, param_3, param_4);

}

int ecall_relay_getRandStringT(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_getRandStringT(global_eid, &ret,NULL, param_1, param_2, param_3, param_4);

return ret;
}

void ecall_relay_greetPeer(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_greetPeer(global_eid, NULL, param_1, param_2, param_3, param_4);

}

void ecall_relay_greetPerson(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_greetPerson(global_eid, NULL, param_1, param_2, param_3, param_4);

}

void ecall_relay_hello(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_hello(global_eid, NULL, param_1, param_2, param_3, param_4, param_5);

}

void ecall_relay_initLedger(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_initLedger(global_eid, NULL, param_1, param_2, param_3);

}

void ecall_relay_ledger_init(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_ledger_init(global_eid, NULL, param_1, param_2, param_3);

}

int ecall_relay_sendGreetings(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_sendGreetings(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

void ecall_relay_transferAsset(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5, int param_6, int param_7)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_transferAsset(global_eid, NULL, param_1, param_2, param_3, param_4, param_5, param_6, param_7);

}

void ecall_relay_Peer(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_Peer(global_eid, NULL, param_1, param_2, param_3, param_4);

}

int ecall_relay_getBalance(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_getBalance(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

int ecall_relay_getLedgerHash(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_getLedgerHash(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

int ecall_relay_getName(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_getName(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

int ecall_relay_getPeerId(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
int ret;
graalsgx_ecall_relay_getPeerId(global_eid, &ret,NULL, param_1, param_2, param_3);

return ret;
}

void ecall_relay_addAssets(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_addAssets(global_eid, NULL, param_1, param_2, param_3, param_4, param_5);

}

void ecall_relay_sayMyName(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_sayMyName(global_eid, NULL, param_1, param_2, param_3, param_4, param_5);

}

void ecall_relay_setBalance(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_setBalance(global_eid, NULL, param_1, param_2, param_3, param_4);

}

void ecall_relay_stringTest(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5, int param_6)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_stringTest(global_eid, NULL, param_1, param_2, param_3, param_4, param_5, param_6);

}

void ecall_relay_setLedgerhash(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_setLedgerhash(global_eid, NULL, param_1, param_2, param_3, param_4);

}

void ecall_doProxyCleanupIn(graal_isolatethread_t* param_0)
{

GRAAL_SGX_INFO();
graalsgx_ecall_doProxyCleanupIn(global_eid, NULL);

}

void ecall_relay_sayHello(graal_isolatethread_t* param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graalsgx_ecall_relay_sayHello(global_eid, NULL, param_1, param_2, param_3);

}

void ocall_mirrorCleanupOut(graal_isolatethread_t* param_0, int param_1)
{/* Do nothing */}
void ecall_mirrorCleanupIn(graal_isolatethread_t* param_0, int param_1)
{

GRAAL_SGX_INFO();
graalsgx_ecall_mirrorCleanupIn(global_eid, NULL, param_1);

}

#if defined(__cplusplus)
}
#endif
