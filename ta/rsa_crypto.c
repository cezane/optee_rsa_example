#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <rsa_ta.h>

//#include <openssl/pem.h>
//#include "../types.h"
//#include "crypto.h"

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

void prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo info;
	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to set key : 0x%x", ret);
		goto err;
	}
err:
        TEE_FreeOperation(handle);
        return 1;
}

static int warp_asym_op(struct rsa_session *sess,
			TEE_OperationMode mode,
			uint32_t alg,
			TEE_Attribute *params,
			uint32_t paramCount,
			void *in_chunk,
			uint32_t in_chunk_len,
			void *out_chunk,
			uint32_t *out_chunk_len) {

	TEE_Result ret = TEE_SUCCESS;
	sess->op_handle = (TEE_OperationHandle)NULL;
	prepare_rsa_operation(&sess->op_handle, alg, mode, sess->key_handle);

//	if (mode == TEE_MODE_ENCRYPT) {
	ret = TEE_AsymmetricEncrypt(sess->op_handle, params, paramCount,
				    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Encrypt failed : 0x%x", ret);
		goto err;
	}

	DMSG("Encrypted data: %s", out_chunk);
/*	} else if (mode == TEE_MODE_DECRYPT) {

		ret = TEE_AsymmetricDecrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			EMSG("Decrypt failed : 0x%x", ret);
			goto err;
		}

	} else {
		goto err;
	}*/

	TEE_FreeOperation(sess->op_handle);
	return 0;

err:
	TEE_FreeOperation(sess->op_handle);
	return 1;
}

//TODO a "prepare" for generating rsa key pair and associating it with the session

TEE_Result RSA_Create_Key_Pair(void *session, uint32_t param_types,
TEE_Param params[4]) {
	TEE_Result ret;
//	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = RSA_KEY_SIZE;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	uint32_t fn_ret = 1; /* Initialized error return */
	struct rsa_session *sess = (struct rsa_session *)session;
	sess->key_handle = (TEE_ObjectHandle)NULL;
	
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	char *plain_txt = params[0].memref.buffer;
	uint32_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	uint32_t cipher_len = params[1].memref.size;

//	void *plain = NULL;
//	void *cipher = NULL;
//	void *dec_plain = NULL;

//	plain = TEE_Malloc(plain_len, 0);
//	cipher = TEE_Malloc(cipher_len, 0);
//	dec_plain = TEE_Malloc(dec_plain_len, 0);
//	if (!plain || !cipher || !dec_plain) {
//		EMSG("Out of memory.");
//		goto err;
//	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(sess->key_handle, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain_txt, plain_len, &cipher, cipher_len))
		goto err;

err:
	TEE_FreeTransientObject(sess->key_handle);
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
	struct rsa_session *sess;

	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct rsa_session *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4]) {
	switch (cmd) {
//	case TA_RSA_CMD_PREPARE:
		//return alloc_resources(session, param_types, params);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_Create_Key_Pair(session, param_types, params);
		//return set_aes_key(session, param_types, params);
	case TA_RSA_CMD_DECRYPT:
//		return reset_aes_iv(session, param_types, params);
//	case TA_RSA_CMD_CIPHER:
//		return RSA_Create_Key_Pair(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
