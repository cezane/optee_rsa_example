#ifndef __RSA_TA_H__
#define __RSA_TA_H__

#define TA_RSA_UUID \
	{ 0x21d38c70, 0xf25a, 0x4b95, \
		{ 0xac, 0x25, 0x07, 0xd1, 0xbf, 0xdb, 0xc1, 0x12 } }

/* The function ID(s) implemented in this TA */
#define TA_RSA_CMD_GENKEYS	0
#define TA_RSA_CMD_ENCRYPT	1
#define TA_RSA_CMD_DECRYPT	2

#endif

