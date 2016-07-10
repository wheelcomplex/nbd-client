#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <err.h>
#include <math.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "check.h"
#include "nbd-client.h"
#include "nbd-protocol.h"

enum {
	NBD_CLIENT_TIMEOUT = 8,
	NBD_REPLY_QUEUE_TIMEOUT = 1,
};

struct nbd_client {
	int sock;
	_Atomic(bool) disconnect;
	uint32_t flags;
	uint64_t size;
};

struct nbd_client *
nbd_client_alloc()
{
	struct nbd_client *client;

	client = (struct nbd_client *)malloc(sizeof (struct nbd_client));
	if (client == NULL) {
		assert(errno == ENOMEM);
		warn("%s: failed to allocate nbd client", __func__);
	}

	return client;
}

void
nbd_client_free(struct nbd_client *client)
{

	free(client);
}

int
nbd_client_init(struct nbd_client *client)
{
	struct timeval tv;
	int sock;
	int on;

	on = 1;

	memset(client, 0, sizeof *client);

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == FAILURE) {
		warn("%s: failed to create socket", __func__);
		return FAILURE;
	}

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on)
	    == FAILURE) {
		warn("%s: failed to set socket option TCP_NODELAY", __func__);
		return FAILURE;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on)
	    == FAILURE) {
		warn("%s: failed to set socket option SO_KEEPALIVE", __func__);
		return FAILURE;
	}
	/*
	tv.tv_sec = NBD_CLIENT_TIMEOUT;
	tv.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv)
	    == FAILURE) {
		warn("%s: failed to set socket option SO_SNDTIMEO", __func__);
		return FAILURE;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv)
	    == FAILURE) {
		warn("%s: failed to set socket option SO_RCVTIMEO", __func__);
		return FAILURE;
	}
	*/
        client->sock = sock;

	return SUCCESS;
}

void
nbd_client_close(struct nbd_client *client)
{

	close(client->sock);
}

int
nbd_client_rights_limit(struct nbd_client *client)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_SHUTDOWN);

	if (cap_rights_limit(client->sock, &rights) == FAILURE) {
		warn("%s: failed to limit capabilities", __func__);
		return FAILURE;
	}

	return SUCCESS;
}

uint64_t
nbd_client_get_size(struct nbd_client *client)
{

	return client->size;
}

bool
nbd_client_get_disconnect(struct nbd_client *client)
{

	return client->disconnect;
}

void
nbd_client_set_disconnect(struct nbd_client *client, bool disconnect)
{

	client->disconnect = disconnect;
}

void
nbd_client_disable_trim(struct nbd_client *client)
{

	client->flags &= ~NBD_FLAG_SEND_TRIM;
}

int
nbd_client_connect(struct nbd_client *client, struct addrinfo *ai)
{
	int sock;

	sock = client->sock;

	if (connect(sock, ai->ai_addr, sizeof *ai->ai_addr) == FAILURE) {
		warn("%s: failed to connect to remote server (%s)",
		     __func__, ai->ai_canonname);
		return FAILURE;
	}

	return SUCCESS;
}

void
nbd_client_shutdown(struct nbd_client *client)
{

	shutdown(client->sock, SHUT_RDWR);
}

static inline char const *
nbd_client_flag_string(uint32_t flag)
{

	switch (flag) {

#define CASE_MESSAGE(c) case c: return #c

		CASE_MESSAGE(NBD_FLAG_HAS_FLAGS);
		CASE_MESSAGE(NBD_FLAG_READ_ONLY);
		CASE_MESSAGE(NBD_FLAG_SEND_FLUSH);
		CASE_MESSAGE(NBD_FLAG_SEND_FUA);
		CASE_MESSAGE(NBD_FLAG_ROTATIONAL);
		CASE_MESSAGE(NBD_FLAG_SEND_TRIM);

#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_client_dump(struct nbd_client *client)
{
	const uint32_t Flags[] = {
		NBD_FLAG_HAS_FLAGS, NBD_FLAG_READ_ONLY, NBD_FLAG_SEND_FLUSH,
		NBD_FLAG_SEND_FUA, NBD_FLAG_ROTATIONAL, NBD_FLAG_SEND_TRIM,
	};
	const size_t FlagsLen = sizeof Flags / sizeof Flags[0];

	uint32_t flags;
	size_t i;

	fprintf(stderr, "\tsock: %d\n", client->sock);
	fprintf(stderr, "\tdisconnect: %s\n",
		client->disconnect ? "true" : "false");
	flags = client->flags;
	fprintf(stderr, "\tflags: %#010x [", flags);
	i = FlagsLen;
	while (i--) {
		char const *name;
		uint32_t value;
		bool match, last;

		value = Flags[i];
		name = nbd_client_flag_string(value);
		match = (flags & value) != 0;
		last = i > 0;

		assert(name != NULL);

		fprintf(stderr, "%s%s", match ? name : "",
			last ? (match ? "|" : "") : "]\n");
	}
	fprintf(stderr, "\tsize: %lu\n", client->size);
}

static inline void
nbd_oldstyle_negotiation_ntoh(struct nbd_oldstyle_negotiation *handshake)
{

	handshake->magic = be64toh(handshake->magic);
	handshake->oldstyle_magic = be64toh(handshake->oldstyle_magic);
	handshake->size = be64toh(handshake->size);
	handshake->flags = be32toh(handshake->flags);
}

static inline bool
nbd_oldstyle_negotiation_is_valid(struct nbd_oldstyle_negotiation *handshake)
{

	if (handshake->magic != NBD_MAGIC) {
		warnx("%s: invalid magic: %#018lx (expected %#018lx)",
		      __func__, handshake->magic, NBD_MAGIC);
		return false;
	}
	if (handshake->oldstyle_magic != NBD_OLDSTYLE_MAGIC) {
		warnx("%s: invalid oldstyle magic: %#018lx (expected %#018lx)",
		      __func__, handshake->oldstyle_magic, NBD_OLDSTYLE_MAGIC);
		return false;
	}
	if (!(handshake->flags & NBD_FLAG_HAS_FLAGS)) {
		warnx("%s: invalid flags: %#010x (expected low bit set)",
		      __func__, handshake->flags);
		return false;
	}

	return true;
}

static inline void
nbd_oldstyle_negotiation_dump(struct nbd_oldstyle_negotiation *handshake)
{
	uint32_t flags = handshake->flags;

	fprintf(stderr, "\tmagic: %#018lx\n", handshake->magic);
	fprintf(stderr, "\toldstyle_magic: %#018lx\n",
		handshake->oldstyle_magic);
	fprintf(stderr, "\tsize: %lu\n", handshake->size);
	fprintf(stderr, "\tflags: %#010x", flags);
	if (!(flags & NBD_FLAG_HAS_FLAGS))
		fprintf(stderr, " (invalid)");
	fprintf(stderr, "\n");
}

static int
nbd_client_oldstyle_handshake(struct nbd_client *client)
{
	struct nbd_oldstyle_negotiation handshake;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, &handshake, sizeof handshake, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof handshake) {
			warn("%s: connection failed", __func__);
			return FAILURE;
		}
		break;
	}

	nbd_oldstyle_negotiation_ntoh(&handshake);

	//fprintf(stderr, "%s: negotiation:\n", __func__);
	//nbd_oldstyle_negotiation_dump(&handshake);

	if (!nbd_oldstyle_negotiation_is_valid(&handshake)) {
		warnx("%s: invalid handshake:", __func__);
		nbd_oldstyle_negotiation_dump(&handshake);
		return FAILURE;
	}

	client->size = handshake.size;
	client->flags = handshake.flags;

	//fprintf(stderr, "%s: client:\n", __func__);
	//nbd_client_dump(client);

	if (!(handshake.flags & NBD_FLAG_SEND_FLUSH))
		warnx("%s: server does not support FLUSH command", __func__);
	if (!(handshake.flags & NBD_FLAG_SEND_TRIM))
		warnx("%s: server does not support TRIM command", __func__);

	return SUCCESS;
}

static inline void
nbd_newstyle_negotiation_ntoh(struct nbd_newstyle_negotiation *handshake)
{

	handshake->magic = be64toh(handshake->magic);
	handshake->newstyle_magic = be64toh(handshake->newstyle_magic);
	handshake->handshake_flags = be16toh(handshake->handshake_flags);
}

#define VALID_NEWSTYLE_FLAGS (NBD_FLAG_FIXED_NEWSTYLE|NBD_FLAG_NO_ZEROES)

static inline bool
nbd_newstyle_negotiation_is_valid(struct nbd_newstyle_negotiation *handshake)
{
	uint16_t flags = handshake->handshake_flags;

	if (handshake->magic != NBD_MAGIC) {
		warnx("%s: invalid magic: %#018lx (expected %#018lx)",
		      __func__, handshake->magic, NBD_MAGIC);
		return false;
	}
	if (handshake->newstyle_magic != NBD_NEWSTYLE_MAGIC) {
		warnx("%s: invalid newstyle magic: %#018lx (expected %#018lx)",
		      __func__, handshake->newstyle_magic, NBD_NEWSTYLE_MAGIC);
		return false;
	}
	if (flags & ~VALID_NEWSTYLE_FLAGS)
		warnx("%s: ignoring unknown handshake flags: %#06x",
		      __func__, flags);
	if (!(flags & NBD_FLAG_FIXED_NEWSTYLE)) {
		warnx("%s: this server does not support the fixed "
		      "newstyle protocol", __func__);
		return false;
	}

	return true;
}

static inline void
nbd_newstyle_negotiation_dump(struct nbd_newstyle_negotiation *handshake)
{
	uint16_t flags = handshake->handshake_flags;

	fprintf(stderr, "\tmagic: %#018lx\n", handshake->magic);
	fprintf(stderr, "\tnewstyle_magic: %#018lx\n",
		handshake->newstyle_magic);
	fprintf(stderr, "\thandshake_flags: %#06x [", flags);
	if (flags & NBD_FLAG_FIXED_NEWSTYLE)
		fprintf(stderr, "FIXED_NEWSTYLE");
	if ((flags & VALID_NEWSTYLE_FLAGS) == VALID_NEWSTYLE_FLAGS)
		fprintf(stderr, "|");
	if (flags & NBD_FLAG_NO_ZEROES)
		fprintf(stderr, "NO_ZEROES");
	fprintf(stderr, "]");
	if (flags & ~VALID_NEWSTYLE_FLAGS)
		fprintf(stderr, " (invalid)");
	fprintf(stderr, "\n");
}

static inline void
nbd_client_flags_set_client_flags(struct nbd_client_flags *client_flags,
				  uint32_t flags)
{

	client_flags->client_flags = htobe32(flags);
}

/*
 * Client handshake
 *
 * If the client and server agree not to send the reserved portion of the
 * EXPORT_NAME option reply, 1 is returned, otherwise 0.
 *
 * Returns -1 if an error is encountered.
 */
static int
nbd_client_newstyle_handshake(struct nbd_client *client)
{
	struct nbd_newstyle_negotiation handshake;
	struct nbd_client_flags response;
	uint32_t client_flags;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, &handshake, sizeof handshake, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof handshake)
			goto connection_fail;
		break;
	}

	nbd_newstyle_negotiation_ntoh(&handshake);

	if (!nbd_newstyle_negotiation_is_valid(&handshake)) {
		warnx("%s: invalid handshake:", __func__);
		nbd_newstyle_negotiation_dump(&handshake);
		return FAILURE;
	}

	client_flags = NBD_CLIENT_FLAG_FIXED_NEWSTYLE;
	if (handshake.handshake_flags & NBD_FLAG_NO_ZEROES)
		client_flags |= NBD_CLIENT_FLAG_NO_ZEROES;

	nbd_client_flags_set_client_flags(&response, client_flags);

	len = send(sock, &response, sizeof response, MSG_NOSIGNAL);
	if (len != sizeof response)
		goto connection_fail;

	client->flags = handshake.handshake_flags << 16;

	return SUCCESS;

 connection_fail:
	warn("%s: connection failed", __func__);
	return FAILURE;
}

static inline void
nbd_option_init(struct nbd_option *option)
{

	memset(option, 0, sizeof *option);
	option->magic = htobe64(NBD_OPTION_MAGIC);
}

static inline void
nbd_option_set_option(struct nbd_option *option, uint32_t opt)
{

	option->option = htobe32(opt);
}

static inline void
nbd_option_set_length(struct nbd_option *option, uint32_t length)
{

	option->length = htobe32(length);
}

static int
nbd_client_send_option(struct nbd_client *client,
		       struct nbd_option *option,
		       size_t length, uint8_t *data)
{
	ssize_t len;
	int sock;

	sock = client->sock;

	len = send(sock, option, sizeof *option, MSG_NOSIGNAL);
	if (len != sizeof *option)
		goto connection_fail;

	if (length == 0)
		return SUCCESS;

	assert(data != NULL);

	len = send(sock, data, length, MSG_NOSIGNAL);
	if (len != length)
		goto connection_fail;

	return SUCCESS;

 connection_fail:
	warn("%s: connection failed", __func__);
	return FAILURE;
}

static inline void
nbd_option_reply_ntoh(struct nbd_option_reply *reply)
{

	reply->magic = be64toh(reply->magic);
	reply->option = be32toh(reply->option);
	reply->type = be32toh(reply->type);
	reply->length = be32toh(reply->length);
}

static inline bool
nbd_option_reply_is_valid(struct nbd_option_reply *reply,
			  struct nbd_option *option)
{
	uint32_t opt;

	opt = be32toh(option->option);

	assert(option->option != NBD_OPTION_EXPORT_NAME);

	if (reply->magic != NBD_OPTION_REPLY_MAGIC) {
		warnx("%s: invalid magic: %#018lx (expected %#018lx)",
		      __func__, reply->magic, NBD_OPTION_REPLY_MAGIC);
		return false;
	}
	if (reply->option != opt) {
		warnx("%s: unexpected option: %#010x (expected %#010x)",
		      __func__, reply->option, opt);
		return false;
	}

	return true;
}

static inline char const *
nbd_option_reply_option_string(struct nbd_option_reply *reply)
{

	switch (reply->option) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"
#define WITHDRAWN " [withdrawn]"

		CASE_MESSAGE(NBD_OPTION_EXPORT_NAME);
		CASE_MESSAGE(NBD_OPTION_ABORT);
		CASE_MESSAGE(NBD_OPTION_LIST);
		CASE_MESSAGE(NBD_OPTION_PEEK_EXPORT) WITHDRAWN;
		CASE_MESSAGE(NBD_OPTION_STARTTLS);
		CASE_MESSAGE(NBD_OPTION_INFO) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_GO) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_STRUCTURED_REPLY) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_BLOCK_SIZE) EXTENSION;

#undef WITHDRAWN
#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline char const *
nbd_option_reply_type_string(struct nbd_option_reply *reply)
{

	switch (reply->type) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"
#define UNUSED    " [unused]"
#define TODO      " [todo]"

		CASE_MESSAGE(NBD_REPLY_ACK);
		CASE_MESSAGE(NBD_REPLY_SERVER);
		CASE_MESSAGE(NBD_REPLY_INFO) EXTENSION;
		CASE_MESSAGE(NBD_REPLY_ERROR_UNSUPPORTED);
		CASE_MESSAGE(NBD_REPLY_ERROR_POLICY);
		CASE_MESSAGE(NBD_REPLY_ERROR_INVALID);
		CASE_MESSAGE(NBD_REPLY_ERROR_PLATFORM) UNUSED;
		CASE_MESSAGE(NBD_REPLY_ERROR_TLS_REQUIRED) TODO;
		CASE_MESSAGE(NBD_REPLY_ERROR_UNKNOWN) EXTENSION;
		CASE_MESSAGE(NBD_REPLY_ERROR_SHUTDOWN);
		CASE_MESSAGE(NBD_REPLY_ERROR_BLOCK_SIZE_REQD) EXTENSION;

#undef TODO
#undef UNUSED
#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_option_reply_dump(struct nbd_option_reply *reply)
{
	char const *option = nbd_option_reply_option_string(reply);
	char const *type = nbd_option_reply_type_string(reply);

	fprintf(stderr, "\tmagic: %#018lx\n", reply->magic);

	if (option == NULL)
		fprintf(stderr, "\toption: [unknown] %#010x (%d)\n",
			reply->option, reply->option);
	else
		fprintf(stderr, "\toption: %s\n", option);

	if (type == NULL)
		fprintf(stderr, "\ttype: [unknown] %#010x (%d)\n",
			reply->type, reply->type);
	else
		fprintf(stderr, "\ttype: %s\n", type);

	fprintf(stderr, "\tlength: %u\n", reply->length);
}

static int
nbd_client_recv_option_reply(struct nbd_client *client,
			     struct nbd_option *option,
			     struct nbd_option_reply *reply,
			     size_t datalen, uint8_t *data)
{
	size_t recvlen;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, reply, sizeof *reply, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof *reply)
			goto connection_fail;
		break;
	}

	nbd_option_reply_ntoh(reply);

	if (!nbd_option_reply_is_valid(reply, option)) {
		warnx("%s: invalid option reply", __func__);
		nbd_option_reply_dump(reply);
		return FAILURE;
	}

	if (reply->length == 0)
		return SUCCESS;

	if (datalen == 0)
		return MOREDATA;

	assert(data != NULL);

	recvlen = MIN(reply->length, datalen);

	while (true) {
		len = recv(sock, data, recvlen, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != recvlen)
			goto connection_fail;
		break;
	}

	if (recvlen > datalen)
		return MOREDATA;

	return SUCCESS;

 connection_fail:
	warn("%s: connection failed", __func__);
	return FAILURE;
}

static inline void
nbd_export_info_ntoh(struct nbd_export_info *info)
{

	info->size = be64toh(info->size);
	info->transmission_flags = be16toh(info->transmission_flags);
}

static int
nbd_client_recv_export_info(struct nbd_client *client,
			    struct nbd_export_info *info)
{
	static size_t const SHORT_INFO_LEN =
		sizeof *info - sizeof info->reserved;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, info, SHORT_INFO_LEN, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != SHORT_INFO_LEN)
			goto connection_fail;
		break;
	}

	nbd_export_info_ntoh(info);

	client->size = info->size;
	client->flags |= info->transmission_flags;

	if ((client->flags >> 16) & NBD_FLAG_NO_ZEROES)
		return SUCCESS;

	while (true) {
		len = recv(sock, info + SHORT_INFO_LEN,
			   sizeof info->reserved, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof info->reserved)
			goto connection_fail;
		break;
	}

	return SUCCESS;

 connection_fail:
	warn("%s: connection failed", __func__);
	return FAILURE;
}

static int
nbd_client_negotiate_options_fixed_newstyle(struct nbd_client *client)
{
	struct nbd_option option;
	struct nbd_option_reply reply;
	struct nbd_export_info info;

	nbd_option_init(&option);

	nbd_option_set_option(&option, NBD_OPTION_EXPORT_NAME);
	if (nbd_client_send_option(client, &option, 0, NULL) == FAILURE) {
		warnx("%s: sending option EXPORT_NAME failed", __func__);
		return FAILURE;
	}
	if (nbd_client_recv_export_info(client, &info) == FAILURE) {
		warnx("%s: receiving export info failed", __func__);
		return FAILURE;
	}

	if (!(info.transmission_flags & NBD_FLAG_SEND_FLUSH)) {
		warnx("%s: server does not support FLUSH command", __func__);
		//return FAILURE;
	}
	if (!(info.transmission_flags & NBD_FLAG_SEND_TRIM)) {
		warnx("%s: server does not support TRIM command", __func__);
		//return FAILURE;
	}

	return SUCCESS;
}

static inline void
nbd_option_reply_server_ntoh(struct nbd_option_reply_server *server_export)
{

	server_export->length = be32toh(server_export->length);
}

static int
nbd_client_negotiate_list_fixed_newstyle(struct nbd_client *client)
{
	struct nbd_option option;
	struct nbd_option_reply reply;
	struct nbd_option_reply_server *server_export;
	size_t const BUFLEN = NAME_MAX;
	char *export_name, buf[BUFLEN + 1];
	size_t recvlen, remaining;
	ssize_t len;
	int rc;

	nbd_option_init(&option);
	nbd_option_set_option(&option, NBD_OPTION_LIST);
	if (nbd_client_send_option(client, &option, 0, NULL) == FAILURE) {
		warnx("%s: sending option LIST failed", __func__);
		return FAILURE;
	}
	while (true) {
		rc = nbd_client_recv_option_reply(client, &option, &reply,
						  BUFLEN, (uint8_t *)buf);
		if (rc == FAILURE) {
			warnx("%s: receiving option LIST reply failed",
			      __func__);
			return FAILURE;
		}
		if (reply.type < 0) {
			char const *msg =
				nbd_option_reply_type_string(&reply);

			if (msg == NULL)
				warnx("%s: unknown server error (%d)\n"
				      "\tbe32toh: %d", __func__,
				      reply.type, be32toh(reply.type));
			else
				warnx("%s: server error: %s", __func__, msg);

			nbd_option_reply_dump(&reply);

			return FAILURE;
		}

		if (reply.type == NBD_REPLY_ACK)
			break;

		assert(reply.type == NBD_REPLY_SERVER);

		server_export = (struct nbd_option_reply_server *)buf;
		nbd_option_reply_server_ntoh(server_export);
		if (server_export->length == 0) {
			printf("\t[default export]\n");
			continue;
		}

		recvlen = MIN(server_export->length, BUFLEN - 4);
		export_name = buf + sizeof *server_export;
		export_name[recvlen] = '\0';

		printf("\t%s", export_name);

		if (rc == SUCCESS) {
			printf("\n");
			continue;
		}

		remaining = server_export->length - BUFLEN;

		assert(remaining > 0);

		do {
			recvlen = MIN(remaining, BUFLEN);
			len = recv(client->sock, buf, recvlen, 0);
			if (client->disconnect)
				return FAILURE;
			if (len == -1 && errno == EINTR)
				continue;
			if (len != recvlen) {
				warn("%s: connection failed", __func__);
				return FAILURE;
			}
			buf[recvlen] = '\0';
			printf("%s", buf);
			remaining -= recvlen;
		} while (remaining > 0);

		printf("\n");
	}

	return SUCCESS;
}

struct handshake_magic {
	uint64_t magic;
	uint64_t style;
} __packed;

static inline void
handshake_magic_ntoh(struct handshake_magic *handshake)
{

	handshake->magic = be64toh(handshake->magic);
	handshake->style = be64toh(handshake->style);
}

static inline void
handshake_magic_dump(struct handshake_magic *handshake)
{

	fprintf(stderr, "\tmagic: %#018lx (expected %#018lx)\n",
		handshake->magic, NBD_MAGIC);
	fprintf(stderr, "\tstyle: %#018lx (expected %#018lx or %#018lx)\n",
		handshake->style, NBD_OLDSTYLE_MAGIC, NBD_NEWSTYLE_MAGIC);
}

int
nbd_client_negotiate(struct nbd_client *client)
{
	struct handshake_magic handshake;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, &handshake, sizeof handshake, MSG_PEEK);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len == -1) {
			warn("%s: connection failed", __func__);
			return FAILURE;
		}
		if (len == sizeof handshake)
			break;
	}

	handshake_magic_ntoh(&handshake);

	if (handshake.magic != NBD_MAGIC) {
		warnx("%s: handshake failed: invalid magic", __func__);
		return FAILURE;
	}

	if (handshake.style == NBD_OLDSTYLE_MAGIC) {

		warnx("%s: oldstyle handshake detected", __func__);

		if (nbd_client_oldstyle_handshake(client) == FAILURE) {
			warnx("%s: handshake failed", __func__);
			return FAILURE;
		}

		return SUCCESS;

	} else if (handshake.style == NBD_NEWSTYLE_MAGIC) {

		warnx("%s: newstyle handshake detected", __func__);

		if (nbd_client_newstyle_handshake(client) == FAILURE) {
			warnx("%s: handshake failed", __func__);
			return FAILURE;
		}

		if (nbd_client_negotiate_options_fixed_newstyle(client)
		    == FAILURE) {
			warnx("%s: option negotiation failed", __func__);
			return FAILURE;
		}

		return SUCCESS;

	}

	warnx("%s: handshake failed: unknown style:", __func__);
	handshake_magic_dump(&handshake);

	return FAILURE;
}

int
nbd_client_list(struct nbd_client *client)
{

	if (nbd_client_newstyle_handshake(client) == FAILURE) {
		warnx("%s: handshake failed", __func__);
		return FAILURE;
	}

	if (nbd_client_negotiate_list_fixed_newstyle(client) == FAILURE) {
		warnx("%s: server listing failed", __func__);
		return FAILURE;
	}

	return SUCCESS;
}

static inline void
nbd_request_init(struct nbd_request *request)
{

	memset(request, 0,  sizeof *request);
	request->magic = htobe32(NBD_REQUEST_MAGIC);
}

static inline void
nbd_request_set_flags(struct nbd_request *request, uint16_t flags)
{

	request->flags = htobe16(flags);
}

static inline void
nbd_request_set_command(struct nbd_request *request, uint16_t command)
{

	request->command = htobe16(command);
}

static inline void
nbd_request_set_handle(struct nbd_request *request, uint64_t handle)
{

	request->handle = htobe64(handle);
}

static inline void
nbd_request_set_offset(struct nbd_request *request, uint64_t offset)
{

	request->offset = htobe64(offset);
}

static inline void
nbd_request_set_length(struct nbd_request *request, uint32_t length)
{

	request->length = htobe32(length);
}

static int
nbd_client_send_request(struct nbd_client *client, uint16_t command,
			uint64_t handle, off_t offset, size_t length,
			size_t datalen, uint8_t *data)
{
	struct nbd_request request;
	size_t sendlen;
	ssize_t len;
	int sock;

	assert(offset + length <= client->size);

	sock = client->sock;

	nbd_request_init(&request);
	nbd_request_set_flags(&request, 0);
	nbd_request_set_command(&request, command);
	nbd_request_set_handle(&request, handle);
	nbd_request_set_offset(&request, offset);
	nbd_request_set_length(&request, length);

	len = send(sock, &request, sizeof request, MSG_NOSIGNAL);
	if (len != sizeof request) {
		warnx("%s: failed to send request header", __func__);
		goto connection_fail;
	}

	if (datalen == 0)
		return SUCCESS;

	assert(data != NULL);

	sendlen = MIN(length, datalen);

	len = send(sock, data, sendlen, MSG_NOSIGNAL);
	if (len != sendlen) {
		warnx("%s: failed to send request data", __func__);
		goto connection_fail;
	}

	if (sendlen < length)
		return MOREDATA;

	return SUCCESS;

 connection_fail:
	warn("%s: connection failed", __func__);
	return FAILURE;
}

int
nbd_client_send_read(struct nbd_client *client, uint64_t handle,
		     off_t offset, size_t length)
{

	return nbd_client_send_request(client, NBD_CMD_READ, handle,
				       offset, length, 0, NULL);
}

int
nbd_client_send_write(struct nbd_client *client, uint64_t handle,
		      off_t offset, size_t length,
		      size_t datalen, uint8_t *data)
{

	return nbd_client_send_request(client, NBD_CMD_WRITE, handle,
				       offset, length, datalen, data);
}

int
nbd_client_send_flush(struct nbd_client *client, uint64_t handle)
{

	if (!(client->flags & NBD_FLAG_SEND_FLUSH)) {
		warnx("%s: unsupported FLUSH operation", __func__);
		return EOPNOTSUPP;
	}

	return nbd_client_send_request(client, NBD_CMD_FLUSH, handle,
				       0, 0, 0, NULL);
}

int
nbd_client_send_trim(struct nbd_client *client, uint64_t handle,
		     off_t offset, size_t length)
{

	if (!(client->flags & NBD_FLAG_SEND_TRIM)) {
		warnx("%s: unsupported TRIM operation", __func__);
		return EOPNOTSUPP;
	}

	return nbd_client_send_request(client, NBD_CMD_TRIM, handle,
				       offset, length, 0, NULL);
}

int
nbd_client_send_disconnect(struct nbd_client *client)
{

	return nbd_client_send_request(client, NBD_CMD_DISCONNECT,
				       (uint64_t)-1, 0, 0, 0, NULL);
}

static inline void
nbd_reply_ntoh(struct nbd_reply *reply)
{

	reply->magic = be32toh(reply->magic);
	reply->error = be32toh(reply->error);
	reply->handle = be64toh(reply->handle);
}

static inline bool
nbd_reply_is_valid(struct nbd_reply *reply)
{

	if (reply->magic != NBD_REPLY_MAGIC) {
		warnx("%s: invalid magic: %#010x (expected %#010x)",
		      __func__, reply->magic, NBD_REPLY_MAGIC);
		return false;
	}

	return true;
}

static inline char const *
nbd_reply_error_string(struct nbd_reply *reply)
{

	switch (reply->error) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"

		CASE_MESSAGE(NBD_EPERM);
		CASE_MESSAGE(NBD_EIO);
		CASE_MESSAGE(NBD_ENOMEM);
		CASE_MESSAGE(NBD_EINVAL);
		CASE_MESSAGE(NBD_ENOSPC);
		CASE_MESSAGE(NBD_EOVERFLOW) EXTENSION;
		CASE_MESSAGE(NBD_ESHUTDOWN);

#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_reply_dump(struct nbd_reply *reply)
{
	char const *error = nbd_reply_error_string(reply);

	fprintf(stderr, "\tmagic: %#010x\n", reply->magic);

	if (error == NULL)
		fprintf(stderr, "\terror: [unknown] %#010x (%d)\n",
			reply->error, reply->error);
	else
		fprintf(stderr, "\terror: %s (%s)\n",
			strerror(reply->error), error);

	fprintf(stderr, "\thandle: %#018lx\n", reply->handle);
}

int
nbd_client_recv_reply_header(struct nbd_client *client, uint64_t *handle)
{
	struct nbd_reply reply;
	ssize_t len;
	int sock;

	sock = client->sock;

	while (true) {
		len = recv(sock, &reply, sizeof reply, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof reply) {
			warn("%s: connection failed", __func__);
			return FAILURE;
		}
		break;
	}

	nbd_reply_ntoh(&reply);

	if (!nbd_reply_is_valid(&reply)) {
		warnx("%s: invalid reply:", __func__);
		goto bad_reply;
	}

	switch (reply.error) {
	case SUCCESS:
		break;
	case NBD_EINVAL:
		warnx("%s: server replied invalid command usage", __func__);
		return EINVAL;
	default:
		warnx("%s: request error:", __func__);
		goto bad_reply;
	}

	*handle = reply.handle;

	return SUCCESS;

 bad_reply:
	nbd_reply_dump(&reply);
	return FAILURE;
}

int
nbd_client_recv_reply_data(struct nbd_client *client, size_t length,
			   size_t buflen, uint8_t *buf)
{
	size_t recvlen;
	ssize_t len;
	int sock;

	if (length == 0)
		return SUCCESS;

	assert(buflen > 0);
	assert(buf != NULL);

	sock = client->sock;

	recvlen = MIN(length, buflen);

	while (true) {
		len = recv(sock, buf, recvlen, MSG_WAITALL);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != recvlen) {
			warn("%s: connection failed", __func__);
			return FAILURE;
		}
		break;
	}

	if (length > buflen)
		return MOREDATA;

	return SUCCESS;
}
