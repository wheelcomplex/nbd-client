#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/cdefs.h>
#include <sys/endian.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <sys/bio.h>
#include <machine/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Block.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <math.h>
#include <signal.h>

#include <geom/gate/g_gate.h>

#include "check.h"

#include "nbd-client.h"
#include "nbd-protocol.h"

#include "ggate.h"

enum {
	DEFAULT_SECTOR_SIZE = 512,
	DEFAULT_GGATE_FLAGS = 0,
};

static void
usage()
{

	fprintf(stderr, "usage: %s address\n", getprogname());
}

static volatile sig_atomic_t disconnect = 0;

typedef void (^disconnect_action_t)(void);
static disconnect_action_t disconnect_action;

static void
signal_handler(int sig, siginfo_t *sinfo, void *uap)
{

	disconnect_action();
}

int
run_loop(ggate_context_t ggate, nbd_client_t nbd)
{
	struct sigaction sa;
	struct g_gate_ctl_io ggio;
	uint8_t buf[MAXPHYS];
	int result;

	ggio = (struct g_gate_ctl_io){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ggate_context_get_unit(ggate),
	};

	disconnect_action = ^{

		nbd_client_set_disconnect(nbd, true);
		disconnect = 1;
	};
	
	sa.sa_sigaction = signal_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGINT, &sa, NULL) == FAILURE) {
		warn("%s: failed to install signal handler", __func__);
		return FAILURE;
	}

	while (!disconnect) {
		ggio.gctl_data = buf;
		ggio.gctl_length = sizeof buf;
		ggio.gctl_error = 0;

		result = ggate_context_ioctl(ggate, G_GATE_CMD_START, &ggio);
		if (result == FAILURE)
			goto fail;

		switch (ggio.gctl_error) {
		case SUCCESS:
			break;
		case ECANCELED:
			return SUCCESS;
		case ENXIO:
		default:
			warnc(ggio.gctl_error,
			      "%s: ggate control operation failed (/dev/%s)",
			      __func__, G_GATE_CTL_NAME);
			goto fail;
		}

		switch (ggio.gctl_cmd) {
		case BIO_READ:
			result = nbd_client_send_read(nbd, ggio.gctl_seq,
						      ggio.gctl_offset,
						      ggio.gctl_length);
			break;
		case BIO_WRITE:
			result = nbd_client_send_write(nbd, ggio.gctl_seq,
						       ggio.gctl_offset,
						       ggio.gctl_length,
						       sizeof buf, buf);
			break;
		case BIO_DELETE:
			result = nbd_client_send_trim(nbd, ggio.gctl_seq,
						      ggio.gctl_offset,
						      ggio.gctl_length);
			break;
		case BIO_FLUSH:
			result = nbd_client_send_flush(nbd, ggio.gctl_seq);
			break;
		default:
			warnx("%s: unsupported operation: %d",
			      __func__, ggio.gctl_cmd);
			result = EOPNOTSUPP;
			break;
		}

		switch (result) {
		case SUCCESS:
			break;
		case EOPNOTSUPP:
			ggio.gctl_error = EOPNOTSUPP;
			goto done;
		case FAILURE:
			warnx("%s: nbd client error", __func__);
			goto fail;
		default:
			warnx("%s: unhandled nbd command result", __func__);
			goto fail;
		}

		result = nbd_client_recv_reply_header(nbd, &ggio.gctl_seq);
		if (result == FAILURE) {
			if (disconnect)
				return SUCCESS;
			warnx("%s: error receiving reply header", __func__);
			goto fail;
		}

		if (ggio.gctl_cmd != BIO_READ)
			goto done;

		result = nbd_client_recv_reply_data(nbd, ggio.gctl_length,
						    sizeof buf, buf);
		if (result == FAILURE) {
			if (disconnect)
				return SUCCESS;
			warnx("%s: error receiving reply data",
			      __func__);
			goto fail;
		}

	done:
		result = ggate_context_ioctl(ggate, G_GATE_CMD_DONE, &ggio);
		if (result == FAILURE) {
			warnx("%s: could not complete transaction", __func__);
			goto fail;
		}

		switch (ggio.gctl_error) {
		case SUCCESS:
		case EOPNOTSUPP:
			break;
		case ECANCELED:
			return SUCCESS;
		case ENXIO:
		default:
			warnc(ggio.gctl_error,
			      "%s: ggate control operation failed (/dev/%s)",
			      __func__, G_GATE_CTL_NAME);
			goto fail;
		}
	}

	return SUCCESS;

 fail:
	ggate_context_cancel(ggate, ggio.gctl_seq);
	return FAILURE;
}

int
main(int argc, char *argv[])
{
	ggate_context_t ggate;
	nbd_client_t nbd;
	char const *host;
	uint64_t size;
	int retval;

	retval = EXIT_FAILURE;
	ggate = NULL;
	nbd = NULL;

	/*
	 * Check for the correct number of arguments and ensure the
	 * geom_gate module is loaded.
	 */
	
	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	host = argv[1];

	if (ggate_load_module() == FAILURE)
		return EXIT_FAILURE;

	/*
	 * Allocate ggate context and nbd client.
	 */

	ggate = ggate_context_alloc();
	nbd = nbd_client_alloc();
	if (ggate == NULL || nbd == NULL)
		goto cleanup;

	/*
	 * Initialize the ggate context and nbd socket.
	 */
	
	ggate_context_init(ggate);
	if (ggate_context_open(ggate) == FAILURE) {
		warnx("cannot open ggate context");
		goto close;
	}	

	if (nbd_client_init(nbd) == FAILURE) {
		warnx("cannot create socket");
		goto close;
	}

	/*
	 * Connect to the nbd server.
	 */
	
	switch (nbd_client_connect(nbd, host, NBD_DEFAULT_PORT)) {

	case NBD_CLIENT_CONNECT_ERROR_USAGE:
		usage();
		goto close;

	case NBD_CLIENT_CONNECT_ERROR_CONNECT:
		warnx("failed to connect to the server");
		goto close;

	default:
		break;
	}

	/*
	 * Negotiate options with the server.
	 */
	
	if (nbd_client_negotiate(nbd) == FAILURE) {
		warnx("failed to negotiate options");
		goto disconnect;
	}

	size = nbd_client_get_size(nbd);

	/*
	 * Create the nbd device.
	 */
	
	if (ggate_context_create_device(ggate, host, NBD_DEFAULT_PORT, "",
					size, DEFAULT_SECTOR_SIZE,
					DEFAULT_GGATE_FLAGS) == FAILURE) {
		warnx("failed to create ggate device");
		goto destroy;
	}

	/*
	 * Handle operations on the ggate device.
	 */

	retval = run_loop(ggate, nbd);

	if (disconnect)
		warnx("interrupted");

	/*
	 * Exit cleanly.
	 */

	/* Destroy the ggate device. */
 destroy:
	ggate_context_cancel(ggate, 0);	
	ggate_context_destroy_device(ggate, true);

	/* Disconnect the NBD client. */
 disconnect:
	if (nbd_client_send_disconnect(nbd) == FAILURE)
		retval = FAILURE;
	nbd_client_shutdown(nbd);

	/* Close open files. */
 close:
	nbd_client_close(nbd);
	ggate_context_close(ggate);

	/* Free data structures. */
 cleanup:
	nbd_client_free(nbd);
	ggate_context_free(ggate);
	
	return retval;
}
