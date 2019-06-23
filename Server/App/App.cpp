#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
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

struct shared_use_st
{
	int written;//flag: 1: writable
	unsigned char text[2000];
};

shared_use_st* create_shm(int key_num, int *shmid) {
	void *shm = NULL;
	struct shared_use_st *shared;
	(*shmid) = shmget((key_t)key_num, sizeof(struct shared_use_st), 0666|IPC_CREAT);
	if((*shmid) == -1)
	{
		fprintf(stderr, "shmget failed\n");
		exit(EXIT_FAILURE);
	}
	shm = shmat((*shmid), 0, 0);
	if(shm == (void*)-1)
	{
		fprintf(stderr, "shmat failed\n");
		exit(EXIT_FAILURE);
	}
	printf("\nMemory attached at %X\n", static_cast<int>(reinterpret_cast<std::uintptr_t>(shm)));

	shared = (struct shared_use_st*)shm;
    shared->written = 1;
    return shared;
}

void send_shm(
    shared_use_st *shm,
    unsigned char* msg,
    uint32_t data_size,
    sgx_rsa3072_public_key_t *pubkey,
    sgx_rsa3072_signature_t *sign) {

    int running = 1;
    bool put = true;

	while(running) {
		if (shm->written == 1) {
			shm->written = 0;
            shm->text[0] = 'S';
            memcpy(shm->text+1, &data_size, sizeof(uint32_t));
            memcpy(shm->text+1+sizeof(uint32_t), msg, data_size);
            memcpy(shm->text+1+sizeof(uint32_t)+data_size, pubkey, sizeof(sgx_rsa3072_public_key_t));
            memcpy(shm->text+1+sizeof(uint32_t)+data_size+sizeof(sgx_rsa3072_public_key_t), sign, sizeof(sgx_rsa3072_signature_t));
            shm->written = 1;
            puts("send_shm: success");
            return;
		} else {
			sleep(1);
            if (put) {
                puts("send_shm: wait written == 1");
                put = false;
            }
        }
	}
}

void receive_shm(shared_use_st *shm) {
    int running = 1;
    bool put = true;
	while(running) {
		if (shm->written == 1 && shm->text[0] == 'C') {
                shm->written = 0;
                shm->text[0] = '\0';
                shm->written = 1;
                puts("receive_shm: success");
                return;
		} else {
			sleep(1);
            if (put) {
                puts("receive_shm: wait written == 1");
                put = false;
            }
        }
	}
}

int _tmain(int argc, _TCHAR *argv[]) {
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
    char p_data[] = "233333";
    sgx_rsa3072_signature_t *signature = (sgx_rsa3072_signature_t*)malloc(sizeof(sgx_rsa3072_signature_t));
    Enclave1_gen_pubkey_and_sign(e1_enclave_id, &status, (const uint8_t*)p_data, sizeof(p_data), &public_key, signature);

    sgx_destroy_enclave(e1_enclave_id);

	struct shared_use_st *shared;
    int shmkey = 2333, shmid;
    shared = create_shm(shmkey, &shmid);
    receive_shm(shared);
    send_shm(
        shared,
        (unsigned char*)p_data,
        sizeof(p_data),
        &public_key,
        signature
    );

    receive_shm(shared);
    sleep(2);

	if(shmdt((void*)shared) == -1)
	{
		fprintf(stderr, "shmdt failed\n");
		exit(EXIT_FAILURE);
	}

	if(shmctl(shmid, IPC_RMID, 0) == -1)
	{
		fprintf(stderr, "shmctl(IPC_RMID) failed\n");
		exit(EXIT_FAILURE);
	}

    return 0;
}
