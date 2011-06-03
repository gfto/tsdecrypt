#ifndef CAMD_H
#define CAMD_H

#include <openssl/aes.h>
#include <openssl/md5.h>

#include "data.h"

struct camd35 {
	int				server_fd;
	struct in_addr	server_addr;
	unsigned int	server_port;
	char			user[64];
	char			pass[64];

	AES_KEY			aes_encrypt_key;
	AES_KEY			aes_decrypt_key;

	uint32_t		auth_token;

	struct key		*key;
};

int camd35_connect		(struct camd35 *c);
void camd35_disconnect	(struct camd35 *c);

int camd35_send_ecm		(struct camd35 *c, uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len);
int camd35_send_emm		(struct camd35 *c, uint16_t ca_id, uint8_t *data, uint8_t data_len);

#endif
