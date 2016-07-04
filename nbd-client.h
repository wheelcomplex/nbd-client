#ifndef _NBD_CLIENT_H_
#define _NBD_CLIENT_H_

#include <sys/types.h>

typedef struct nbd_client *nbd_client_t;

nbd_client_t nbd_client_alloc();
void nbd_client_free(nbd_client_t client);

int nbd_client_init(nbd_client_t client);
void nbd_client_close(nbd_client_t client);

uint64_t nbd_client_get_size(nbd_client_t client);

bool nbd_client_get_disconnect(nbd_client_t client);
void nbd_client_set_disconnect(nbd_client_t client, bool disconnect);

enum {
	NBD_CLIENT_CONNECT_OK = 0,
	
	NBD_CLIENT_CONNECT_ERROR_USAGE = -1,
	NBD_CLIENT_CONNECT_ERROR_CONNECT = -2,
};

int nbd_client_connect(nbd_client_t client, char const *address,
		       uint16_t port);
void nbd_client_shutdown(nbd_client_t client);

int nbd_client_list(nbd_client_t client);

int nbd_client_negotiate(nbd_client_t client);
int nbd_client_send_read(nbd_client_t client, uint64_t handle,
			 off_t offset, size_t length);
int nbd_client_send_write(nbd_client_t client, uint64_t handle,
			  off_t offset, size_t length,
			  size_t datalen, uint8_t *data);
int nbd_client_send_flush(nbd_client_t client, uint64_t handle);
int nbd_client_send_trim(nbd_client_t client, uint64_t handle,
			 off_t offset, size_t length);
int nbd_client_send_disconnect(nbd_client_t client);
int nbd_client_recv_reply_header(nbd_client_t client, uint64_t *handle);
int nbd_client_recv_reply_data(nbd_client_t client, size_t length,
			       size_t buflen, uint8_t *buf);

#endif /* #ifndef _NBD_CLIENT_H_ */
