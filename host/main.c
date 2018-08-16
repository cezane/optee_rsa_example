#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#include <rsa_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_RSA_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = in_sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = out_sz;

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x",
			res, origin);
}

int main(int argc, char *argv[])
{
	struct ta_attrs ta;
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	//declare/initialize my variables
	//pubkey
	
	prepare_ta_session(&ta);
	
	printf("\nType something to be encrypted and decrypted in the TA:\n");
	fflush(stdin); //setbuf(stdin, NULL);
	fgets(clear, sizeof(clear), stdin);

	rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024);

	//Register the RSA public key 
/*	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.size = sizeof(pubkey);
	op.params[0].tmpref.buffer = pubkey;*/

	terminate_tee_session(&ta);
	return 0;
}
