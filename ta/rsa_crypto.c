#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

#include "../types.h"
#include "crypto.h"

static int warp_asym_op(TEE_ObjectHandle key,
			TEE_OperationMode mode,
			uint32_t alg,
			TEE_Attribute *params,
			uint32_t paramCount,
			void *in_chunk,
			uint32_t in_chunk_len,
			void *out_chunk,
			uint32_t *out_chunk_len) {

	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle handle = (TEE_OperationHandle)NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	if (mode == TEE_MODE_ENCRYPT) {

		ret = TEE_AsymmetricEncrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Encrypt failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_DECRYPT) {

		ret = TEE_AsymmetricDecrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Decrypt failed : 0x%x", ret);
			goto err;
		}

	} else {
		goto err;
	}

	TEE_FreeOperation(handle);
	return 0;

err:
	TEE_FreeOperation(handle);
	return 1;
}

TEE_Result RSA_Create_Key_Par() {
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 1024;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		DMSG("Generate key failure : 0x%x", ret);
		goto err;
	}


err:
	TEE_FreeTransientObject(rsa_keypair);
//	TEE_Free(plain);
//	TEE_Free(dec_plain);
//	TEE_Free(cipher);

	if (fn_ret == 0)
		DMSG("----");

	return fn_ret;
}

TEE_Result TA_CreateEntryPoint(void) {
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session) {
	struct aes_cipher *sess;

	/*
	 * Allocate and init ciphering materials for the session.
	 * The address of the structure is used as session ID for
	 * the client.
	 */
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4]) {
	switch (cmd) {
	case TA_RSA_CMD_PREPARE:
		return alloc_resources(session, param_types, params);
	case TA_RSA_CMD_ENC:
		return set_aes_key(session, param_types, params);
	case TA_RSA_CMD_DEC:
		return reset_aes_iv(session, param_types, params);
	case TA_RSA_CMD_CIPHER:
		return cipher_buffer(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
