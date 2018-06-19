ifndef __RSA_TA_H__
#define __RSA_TA_H__

#define TA_HOTP_UUID \
	{ 0x484d4143, 0x2d53, 0x4841, \
		{ 0x31, 0x20, 0x4a, 0x6f, 0x63, 0x6b, 0x65, 0x42 } }

/* The function ID(s) implemented in this TA */
#define TA_RSA_CMD_REGISTER_PUB_KEY	0
#define TA_RSA_CMD_ENCRYPT_DATA		1
#define TA_RSA_CMD_DECRYPT_DATA		2

#endif

