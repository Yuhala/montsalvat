/* Generated by GraalVM SGXProxyGenerator. */ 

#if defined(__cplusplus)
extern "C" {
#endif

void graalsgx_ocall_relay_Main(void *param_0, int param_1)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_Main(temp_iso, param_1);


}

void graalsgx_ocall_relay_addObjs(void *param_0, int param_1, char* param_2, int param_3, int param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_addObjs(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

void graalsgx_ocall_relay_doConcreteIn(void *param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_doConcreteIn(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

void graalsgx_ocall_relay_doConcreteOut(void *param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_doConcreteOut(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

void graalsgx_ocall_relay_doConsistencyTest(void *param_0, int param_1, char* param_2, int param_3, int param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_doConsistencyTest(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

void graalsgx_ocall_relay_doProxyOut(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_doProxyOut(temp_iso, param_1, param_2, param_3, param_4);


}

void graalsgx_ocall_relay_gcTest(void *param_0, int param_1, char* param_2, int param_3, int param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_gcTest(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

int graalsgx_ocall_relay_getRandString(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
int ret = relay_getRandString(temp_iso, param_1, param_2, param_3, param_4);


return ret;
}

void graalsgx_ocall_relay_doProxyIn(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_doProxyIn(temp_iso, param_1, param_2, param_3, param_4);


}

void graalsgx_ocall_relay_removeObjs(void *param_0, int param_1, char* param_2, int param_3, int param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_removeObjs(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

int graalsgx_ocall_relay_getName(void *param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
int ret = relay_getName(temp_iso, param_1, param_2, param_3);


return ret;
}

void graalsgx_ocall_relay_Person(void *param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_Person(temp_iso, param_1, param_2, param_3);


}

int graalsgx_ocall_relay_getPersonId(void *param_0, int param_1, char* param_2, int param_3)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
int ret = relay_getPersonId(temp_iso, param_1, param_2, param_3);


return ret;
}

void graalsgx_ocall_relay_setId(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_setId(temp_iso, param_1, param_2, param_3, param_4);


}

void graalsgx_ocall_doProxyCleanupIn(void *param_0)
{/* Do nothing */}
void graalsgx_ocall_mirrorCleanupOut(void *param_0, int param_1)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
mirrorCleanupOut(temp_iso, param_1);


}

void graalsgx_ocall_mirrorCleanupIn(void *param_0, int param_1)
{/* Do nothing */}
void graalsgx_ocall_relay_Untrusted(void *param_0, int param_1, int param_2)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_Untrusted(temp_iso, param_1, param_2);


}

void graalsgx_ocall_relay_sayMyName(void *param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_sayMyName(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

int graalsgx_ocall_relay_getRandStringU(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
int ret = relay_getRandStringU(temp_iso, param_1, param_2, param_3, param_4);


return ret;
}

void graalsgx_ocall_relay_setNameU(void *param_0, int param_1, char* param_2, int param_3, char* param_4, int param_5)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_setNameU(temp_iso, param_1, param_2, param_3, param_4, param_5);


}

void graalsgx_ocall_relay_setNamesU(void *param_0, int param_1, char* param_2, int param_3, int param_4)
{

GRAAL_SGX_INFO();
graal_isolatethread_t* temp_iso = global_app_iso;
relay_setNamesU(temp_iso, param_1, param_2, param_3, param_4);


}

#if defined(__cplusplus)
}
#endif