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

    return SGX_SUCCESS;
}

int _tmain(int argc, _TCHAR *argv[])
{
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS)
    {
        printf("Load Enclave Failure\n");
        exit(-1);
    }

    printf("Enclave1 - EnclaveID %" PRIx64 "\n", e1_enclave_id);

    sgx_rsa3072_public_key_t public_key;
    char p_data[12] = "23333333333";
    sgx_rsa3072_signature_t *signature = (sgx_rsa3072_signature_t*)malloc(sizeof(sgx_rsa3072_signature_t));
    Enclave1_gen_pubkey_and_sign(e1_enclave_id, &status, (const uint8_t*)p_data, sizeof(char)*12, &public_key, signature);

    sgx_destroy_enclave(e1_enclave_id);

    return 0;
}
