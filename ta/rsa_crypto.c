#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

#include "../types.h"
#include "crypto.h"

TEE_Result RSA_Create_Key_Par() {
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 1024;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

}

TEE_Result TA_CreateEntryPoint(void) {
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	/* Nothing to do */
}
