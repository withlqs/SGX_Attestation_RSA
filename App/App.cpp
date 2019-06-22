#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define UNUSED(val) (void)(val)
#define TCHAR char
#define _TCHAR char
#define _T(str) str
#define scanf_s scanf
#define _tmain main

extern std::map<sgx_enclave_id_t, uint32_t> g_enclave_id_map;

sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    return SGX_SUCCESS;
}

int _tmain(int argc, _TCHAR *argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
        exit(-1);
    }

    printf("Enclave1 - EnclaveID %" PRIx64 "\n", e1_enclave_id);
    printf("Enclave2 - EnclaveID %" PRIx64 "\n", e2_enclave_id);

    //Test Create session between Enclave1(Source) and Enclave2(Destination)
    status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
    if (status == SGX_SUCCESS && ret_status == 0)
    {
        printf("open session, ok.\n");
    }
    else
    {
        printf("open session, failed.\n");
        exit(-1);
    }

    //Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
    status = Enclave1_test_enclave_to_enclave_call(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
    if (status == SGX_SUCCESS && ret_status == 0)
    {
        printf("E1 call E2, ok.\n");
    }
    else
    {
        printf("E1 call E2, failed.\n");
        exit(-1);
    }

    //Test message exchange between Enclave1(Source) and Enclave2(Destination)
    status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
    if (status == SGX_SUCCESS && ret_status == 0)
    {
        printf("E1 to E2, ok.\n");
    }
    else
    {
        printf("E1 to E2, failed.\n");
        exit(-1);
    }

    //Test Closing Session between Enclave1(Source) and Enclave2(Destination)
    status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
    if (status == SGX_SUCCESS && ret_status == 0)
    {
        printf("close session, ok.\n");
    }
    else
    {
        printf("close session, failed.\n");
        exit(-1);
    }

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);

    return 0;
}
