#ifndef _NBD_PROTOCOL_H_
#define _NBD_PROTOCOL_H_

#include <sys/cdefs.h>
#include <sys/types.h>

/**
 ** Network protocol header structs and values
 **/

#define NBD_DEFAULT_PORT "10809"

/*
 * Negotiation handshake
 *
 * When the client connects, the server sends a handshake packet with the
 * handshake flags.  The client responds with its client flags, which must
 * include the FIXED_NEWSTYLE flag.
 */

#define NBD_MAGIC 0x4e42444d41474943UL
#define NBD_NEWSTYLE_MAGIC 0x49484156454F5054UL

#define NBD_FLAG_FIXED_NEWSTYLE (1 << 0)
#define NBD_FLAG_NO_ZEROES      (1 << 1)

struct nbd_negotiation {
	uint64_t magic;
	uint64_t newstyle_magic;
	uint16_t handshake_flags;
} __packed;


#define NBD_CLIENT_FLAG_FIXED_NEWSTYLE NBD_FLAG_FIXED_NEWSTYLE
#define NBD_CLIENT_FLAG_NO_ZEROES      NBD_FLAG_NO_ZEROES

struct nbd_client_flags {
	uint32_t client_flags;
} __packed;


/*
 * Option haggling
 *
 * After the initial handshake, the client requests desired options and the
 * server replies to each option acknowledging if supported or with an
 * error if the option is unsupported.
 *
 * The client must only negotiate one option at a time.  Some options will
 * have multiple replies from the server.  The client must wait until the
 * final reply for an option is received before moving on.
 *
 * Option haggling is completed when the client sends either of the
 * following options:
 *  - EXPORT_NAME (transition to transmission mode)
 *  - ABORT (soft disconnect, server should acknowledge)
 * Alternatively, a hard disconnect may occur by disconnecting the TCP
 * session.
 *
 * The server's reply to the EXPORT_NAME option is unique.  EXPORT_NAME
 * signals a transition into transmission mode, and the server sends the
 * length of the export in bytes, the transmission flags, and unless the
 * NO_ZEROES flag has been negotiated during the handshake, 124 zero bytes
 * (reserved for future use).  If the server instead refuses the requested
 * export, it terminates closes the TCP session.
 *
 * Note: The transmission flags for the server's reply to EXPORT_NAME are
 * defined in the next section.
 */

#define NBD_OPTION_MAGIC NBD_NEWSTYLE_MAGIC

enum {
	NBD_OPTION_EXPORT_NAME      = 1,
	NBD_OPTION_ABORT            = 2,
	NBD_OPTION_LIST             = 3,
	NBD_OPTION_PEEK_EXPORT      = 4, // withdrawn
	NBD_OPTION_STARTTLS         = 5,
	NBD_OPTION_INFO             = 6, // experimental extension
	NBD_OPTION_GO               = 7, // experimental extension
	NBD_OPTION_STRUCTURED_REPLY = 8, // experimental extension
	NBD_OPTION_BLOCK_SIZE       = 9, // experimental extension
};

struct nbd_option {
	uint64_t magic;
	uint32_t option;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


#define NBD_OPTION_REPLY_MAGIC 0x3e889045565a9UL

enum {
	NBD_REPLY_ACK    = 1,
	NBD_REPLY_SERVER = 2,
	NBD_REPLY_INFO   = 3, // experimental extension

	NBD_REPLY_ERROR                 = (1 << 31),
	NBD_REPLY_ERROR_UNSUPPORTED     = (1 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_POLICY          = (2 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_INVALID         = (3 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_PLATFORM        = (4 | NBD_REPLY_ERROR), // unused
	NBD_REPLY_ERROR_TLS_REQUIRED    = (5 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_UNKNOWN         = (6 | NBD_REPLY_ERROR), // experimental extension
	NBD_REPLY_ERROR_SHUTDOWN        = (7 | NBD_REPLY_ERROR),
	NBD_REPLY_ERROR_BLOCK_SIZE_REQD = (8 | NBD_REPLY_ERROR), // experimental extension
};

struct nbd_option_reply {
	uint64_t magic;
	uint32_t option;
	int32_t type;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


struct nbd_option_reply_server {
	uint32_t length;
	// char export_name[]; (sent separately)
} __packed;


/* See the next section for the definitions of the transmission flags. */

struct nbd_export_info {
	uint64_t size;
	uint16_t transmission_flags;
	uint8_t reserved[124];
} __packed;


/*
 * Transmission
 *
 * The client sends a request, and the server replies.  Replies may not
 * necessarily be in the same order as the requests, so the client assigns
 * a handle to each request.  The handle must be unique among all active
 * requests.  The server replies using the same handle to associate the
 * reply with the correct transaction.
 *
 * The following ordering constraints apply to transmissions:
 *  - All write commands must be completed before a flush command can be
 *    processed.
 *  - Data sent by the client with the FUA flag set must be written to
 *    persistent storage by the server before the server may reply.   
 *
 * Only the client may cleanly disconnect during transmission, by sending
 * the DISCONNECT command.  Either the client or server may perform a hard
 * disconnect by dropping the TCP session.  If a client receives ESHUTDOWN
 * errors it must attempt a clean disconnect.
 *
 * Note on errors: The server should map EDQUOT and EFBIG to ENOSPC.
 */

#define NBD_REQUEST_MAGIC 0x25609513

#define NBD_FLAG_HAS_FLAGS  (1 << 0)
#define NBD_FLAG_READ_ONLY  (1 << 1)
#define NBD_FLAG_SEND_FLUSH (1 << 2)
#define NBD_FLAG_SEND_FUA   (1 << 3) /* FUA = force unit access */
#define NBD_FLAG_ROTATIONAL (1 << 4) /* use elevator algorithm */
#define NBD_FLAG_SEND_TRIM  (1 << 5)

enum {
	NBD_CMD_READ        = 0,
	NBD_CMD_WRITE       = 1,
	NBD_CMD_DISCONNECT  = 2,
	NBD_CMD_FLUSH       = 3,
	NBD_CMD_TRIM        = 4,
};

struct nbd_request {
	uint32_t magic;
	uint16_t flags;
	uint16_t command;
	uint64_t handle;
	uint64_t offset;
	uint32_t length;
	// uint8_t data[]; (sent separately)
} __packed;


#define NBD_REPLY_MAGIC 0x67446698

enum {
	NBD_EPERM     = 1,
	NBD_EIO       = 5,
	NBD_ENOMEM    = 12,
	NBD_EINVAL    = 22,
	NBD_ENOSPC    = 28,
	NBD_EOVERFLOW = 75, // (experimental extension)
	NBD_ESHUTDOWN = 108,
};

struct nbd_reply {
	uint32_t magic;
	uint32_t error;
	uint64_t handle;
	// uint8_t data[]; (sent separately)
} __packed;

#endif /* #ifndef _NBD_PROTOCOL_H_ */
