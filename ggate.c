#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <geom/gate/g_gate.h>

#include "check.h"
#include "ggate.h"

int
ggate_load_module()
{

	if (modfind("g_gate") != FAILURE)
		return SUCCESS;
	
	if (kldload("geom_gate") == FAILURE
	    || modfind("g_gate") == FAILURE) {
		if (errno != EEXIST) {
			warnx("geom_gate module not available!");
			return FAILURE;
		}
	}

	return SUCCESS;
}

struct ggate_context {
	int ctl;
	int unit;
};

struct ggate_context *
ggate_context_alloc()
{
	struct ggate_context *ctx;

	ctx = (struct ggate_context *)malloc(sizeof (struct ggate_context));
	if (ctx == NULL) {
		assert(errno == ENOMEM);
		warn("%s: failed to allocate ggate context", __func__);
	}

	return ctx;
}

void
ggate_context_init(struct ggate_context *ctx)
{

	ctx->ctl = -1;
	ctx->unit = G_GATE_UNIT_AUTO;
}

void
ggate_context_free(struct ggate_context *ctx)
{

	free(ctx);
}

int
ggate_context_open(struct ggate_context *ctx)
{
	int fd;

	fd = open("/dev/" G_GATE_CTL_NAME, O_RDWR);
	if (fd == FAILURE) {
		warn("%s: failed to open control device (/dev/%s)",
		     __func__, G_GATE_CTL_NAME);
		return FAILURE;
	}

	ctx->ctl = fd;
	
	return SUCCESS;
}

void
ggate_context_close(struct ggate_context *ctx)
{

	close(ctx->ctl);
	ctx->ctl = -1;
}

int
ggate_context_get_unit(struct ggate_context *ctx)
{

	return ctx->unit;
}

int
ggate_context_ioctl(struct ggate_context *ctx, uint64_t req, void *data)
{
	int error;
	
	while (ioctl(ctx->ctl, req, data) == FAILURE) {
		if (errno == EINTR)
			continue;

		warn("%s: ioctl failed (/dev/%s)", __func__, G_GATE_CTL_NAME);

		return FAILURE;
	}

	return SUCCESS;
}

static inline void
g_gate_ctl_create_dump(struct g_gate_ctl_create *ggioc)
{
	
	fprintf(stderr, "\tgctl_version: %u\n", ggioc->gctl_version);
	fprintf(stderr, "\tgctl_mediasize: %ld\n", ggioc->gctl_mediasize);
	fprintf(stderr, "\tgctl_sectorsize: %u\n", ggioc->gctl_sectorsize);
	fprintf(stderr, "\tgctl_flags: %#010x\n", ggioc->gctl_flags);
	fprintf(stderr, "\tgctl_maxcount: %u\n", ggioc->gctl_maxcount);
	fprintf(stderr, "\tgctl_timeout: %u\n", ggioc->gctl_timeout);
	fprintf(stderr, "\tgctl_name: %.*s\n", NAME_MAX, ggioc->gctl_name);
	fprintf(stderr, "\tgctl_info: %.*s\n", G_GATE_INFOSIZE, ggioc->gctl_info);
	fprintf(stderr, "\tgctl_readprov: %.*s\n", NAME_MAX, ggioc->gctl_readprov);
	fprintf(stderr, "\tgctl_readoffset: %ld\n", ggioc->gctl_readoffset);
	fprintf(stderr, "\tgctl_unit: %d\n", ggioc->gctl_unit);
}

int
ggate_context_create_device(struct ggate_context *ctx, char const *host,
			    char const *port, char const *path,
			    off_t mediasize, uint32_t sectorsize,
			    uint32_t flags)
{
	struct g_gate_ctl_create ggioc;
	int unit;

	unit = ctx->unit;

	ggioc = (struct g_gate_ctl_create){
		.gctl_version = G_GATE_VERSION,
		.gctl_mediasize = mediasize,
		.gctl_sectorsize = sectorsize,
		.gctl_flags = flags,
		.gctl_maxcount = GGATE_DEFAULT_QUEUE_SIZE,
		.gctl_timeout = GGATE_DEFAULT_TIMEOUT,
		.gctl_unit = unit,
	};

	snprintf(ggioc.gctl_info, sizeof ggioc.gctl_info,
		 "%s:%s %s (nbd)", host, port, path);

	if (ggate_context_ioctl(ctx, G_GATE_CMD_CREATE, &ggioc) == FAILURE) {
		warnx("%s: failed to create ggate device", __func__);
		g_gate_ctl_create_dump(&ggioc);
		return FAILURE;
	}

	if (unit == G_GATE_UNIT_AUTO) {
		printf("%s%u\n", G_GATE_PROVIDER_NAME, ggioc.gctl_unit);
		fflush(stdout);
	}

	ctx->unit = ggioc.gctl_unit;

	return SUCCESS;
}

int
ggate_context_destroy_device(struct ggate_context *ctx, bool force)
{
	struct g_gate_ctl_destroy ggioc;

	ggioc = (struct g_gate_ctl_destroy){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ctx->unit,
		.gctl_force = force ? 1 : 0,
	};

	if (ggate_context_ioctl(ctx, G_GATE_CMD_DESTROY, &ggioc) == FAILURE) {
		warnx("%s: failed to destroy ggate device", __func__);
		return FAILURE;
	}

	ctx->unit = G_GATE_UNIT_AUTO;

	return SUCCESS;
}

int
ggate_context_cancel(struct ggate_context *ctx, uintptr_t seq)
{
	struct g_gate_ctl_cancel ggioc;

	ggioc = (struct g_gate_ctl_cancel){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ctx->unit,
		.gctl_seq = seq,
	};

	if (ggate_context_ioctl(ctx, G_GATE_CMD_CANCEL, &ggioc) == FAILURE) {
		warnx("%s: failed to cancel ggate command %lx", __func__, seq);
		return FAILURE;
	}

	return SUCCESS;
}
