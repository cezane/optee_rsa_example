include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#include <rsa_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session session;
	TEEC_Operation op;
	TEEC_Result res;
	TEEC_UUID uuid = TA_RSA_UUID;

	//declare/initialize my variables
	//pubkey

	// Initialize a context, connecting CA to TEE OS (OPTEE)
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
				NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x",
			res, err_origin);

	//Register the RSA public key 
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.size = sizeof(pubkey);
	op.params[0].tmpref.buffer = pubkey;
}
