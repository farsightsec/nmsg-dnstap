/*
 * Copyright (c) 2023 by DomainTools LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#include "libmy/argv.h"
#include "libmy/my_alloc.h"

#include "fstrm_srv.h"

#include <nmsg.h>
#include <nmsg/base/defs.h>

#include <zmq.h>

struct globals;
struct cmdline_args;
struct conn;

enum log_level {
	LOG_CRITICAL		= 0,
	LOG_ERROR		= 1,
	LOG_WARNING		= 2,
	LOG_INFO		= 3,
	LOG_DEBUG		= 4,
	LOG_TRACE		= 5,
};

struct conn {
	struct globals		*ctx;
	size_t			bytes_read;
	size_t			count_read;
	int			fd;
};

struct globals {
	struct cmdline_args	*args;

	struct sockaddr_storage	ss;
	socklen_t		ss_len;

	struct fs_ctx		*fsrv_ctx;		/* fstrm context. */
	struct fs_listener	*fsrv_lstnr;		/* fstrm listener. */

	nmsg_msgmod_t		mod_dnstap;		/* DNSTAP module. */
	void			*clos_dnstap;

	void			*zmq_ctx;		/* 0mq context */

	size_t			bytes_written;
	size_t			count_written;
	size_t			capture_highwater;
};

struct cmdline_args {
	const char		*str_content_type;
	const char		*str_read_unix;
	const char		*str_read_tcp_address;
	const char		*str_read_tcp_port;
	argv_array_t		w_sock;
	argv_array_t		w_zmq;
	int			buffer_size;
	unsigned		debug;
	bool			help;
};

static struct globals		g_program_ctx;
static struct cmdline_args	g_program_args;

/* Default content type to receive. */
static const char *s_dflt_content_type = "protobuf:dnstap.Dnstap";

static argv_t g_args[] = {
	{ 'h',	"help",
		ARGV_BOOL,
		&g_program_args.help,
		NULL,
		"display this help text and exit" },

	{ 'b',	"buffersize",
		ARGV_INT,
		&g_program_args.buffer_size,
		"<SIZE>",
		"read buffer size, in bytes (default 262144)" },

	{ 'd',	"debug",
		ARGV_INCR,
		&g_program_args.debug,
		NULL,
		"increment debugging level" },

	{ 't',	"type",
		ARGV_CHAR_P,
		&g_program_args.str_content_type,
		"<STRING>",
		"Frame Streams content type" },

	{ 'u',	"unix",
		ARGV_CHAR_P,
		&g_program_args.str_read_unix,
		"<FILENAME>",
		"Unix socket path to read from" },

	{ 'a',	"tcp",
		ARGV_CHAR_P,
		&g_program_args.str_read_tcp_address,
		"<ADDRESS>",
		"TCP socket address to read from" },

	{ 'p',	"port",
		ARGV_CHAR_P,
		&g_program_args.str_read_tcp_port,
		"<PORT>",
		"TCP socket port to read from" },

	{ 's', "writesock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&g_program_args.w_sock,
		"<sep>",
		"write nmsg data to UDP socket (addr/port)" },

	{ 'w', "writezsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&g_program_args.w_zmq,
		"<zep>",
		"write nmsg data to ZeroMQ endpoint" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 },
};

/* Initialize new client-connection. */
static struct conn *
conn_init(struct globals *ctx, int fd)
{
	struct conn *conn;

	conn = my_calloc(1, sizeof(*conn));
	conn->ctx = ctx;
	conn->fd = fd;

	return(conn);
}

static void
conn_destroy(struct conn **conn)
{
	my_free(*conn);
}

static void
log_mesg(unsigned, int, const char*, ...) __attribute__ ((format (printf, 3, 4)));

static void
log_mesg(unsigned level, int fd, const char *format, ...)
{
	va_list args;
	time_t time_now;
	struct tm tm;

	if (level > g_program_args.debug)
		return;

	time_now = time(NULL);
	localtime_r(&time_now, &tm);
	fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	if (fd >= 0)
		fprintf(stderr, "fd=%d ", fd);

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fputc('\n', stderr);
}

static void __attribute__((noreturn))
usage(const char *msg)
{
	if (msg != NULL)
		fprintf(stderr, "%s: Usage error: %s\n", argv_program, msg);
	argv_usage(g_args, ARGV_USAGE_DEFAULT);
	argv_cleanup(g_args);
	exit(EXIT_FAILURE);
}

static bool
parse_args(const int argc, char **argv)
{
	argv_version_string = PACKAGE_VERSION;

	if (argv_process(g_args, argc, argv) != 0)
		return(false);

	/* Validate args. */
	if (g_program_args.help)
		return(false);
	if (g_program_args.str_content_type == NULL)
		g_program_args.str_content_type = s_dflt_content_type;
	if (g_program_args.str_read_unix == NULL &&
	    g_program_args.str_read_tcp_address == NULL)
		usage("One of --unix or --tcp must be set");
	if (g_program_args.str_read_tcp_address != NULL &&
	    g_program_args.str_read_tcp_port == NULL)
		usage("If --tcp is set, --port must also be set");
	g_program_ctx.capture_highwater = 262144;
	if (g_program_args.buffer_size > 0)
		g_program_ctx.capture_highwater = (size_t)g_program_args.buffer_size;
	/* Must have at least one endpoint for sending NMSG data. */
	if (ARGV_ARRAY_COUNT(g_program_args.w_zmq) < 1 &&
	    ARGV_ARRAY_COUNT(g_program_args.w_sock) < 1)
		usage("Endpoint to write Frame Streams data to (--write / --writesock) is not set");

	return(true);
}

/*
 * Parse strings to extract IP-address & port.
 *
 * Returns: 0 upon success, -1 if bad port, -2 if bad address
 */
static int
parse_port_addr(const char *addr, const char *portstr, struct sockaddr_storage *ss, socklen_t *ss_len)
{
	struct sockaddr_in *sai = (struct sockaddr_in*) ss;
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6*) ss;
	uint64_t port;
	char *endptr = NULL;

	port = strtoul(portstr, &endptr, 0);
	if (*endptr != '\0' || port >= UINT16_MAX)
		return(-1);

	if (inet_pton(AF_INET6, addr, &sai6->sin6_addr) == 1) {
		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
		*ss_len = sizeof(struct sockaddr_in6);
	} else if (inet_pton(AF_INET, addr, &sai->sin_addr) == 1) {
		sai->sin_family = AF_INET;
		sai->sin_port = htons(port);
		*ss_len = sizeof(struct sockaddr_in);
	} else
	    return(-2);

	return(0);
}

/* Parse connection spec of the form "addr/port" */
static bool
parse_sockspec(const char *sockspec, struct sockaddr_storage *ss, socklen_t *ss_len)
{
	char *addr, *t;
	bool res = false;

	addr = strdup(sockspec);
	if (addr == NULL)
		return(false);

	t = strchr(addr, '/');	/* Tokenize socket address */
	if (t != NULL) {
		*t++ = 0;

		if (parse_port_addr(addr, t, ss, ss_len) == 0)
			res = true;
	}

	free(addr);

	return(res);
}

/* Setup UNIX datagram socket to receive incoming FSTRM data. */
static bool
setup_read_unix(struct globals *ctx)
{
	int ret;
	struct sockaddr_un *sa = (struct sockaddr_un *) &ctx->ss;

	if (ctx->args->str_read_tcp_port != NULL)
		fputs("Warning: Ignoring --port with --unix\n", stderr);

	/* Construct sockaddr_un structure. */
	if (strlen(ctx->args->str_read_unix) + 1 > sizeof(sa->sun_path))
	{
		fprintf(stderr, "%s: ERROR: UNIX socket path is too long '%s'\n",
			argv_program, ctx->args->str_read_unix);
		return(false);
	}
	sa->sun_family = AF_UNIX;
	strncpy(sa->sun_path, ctx->args->str_read_unix, sizeof(sa->sun_path) - 1);
	ctx->ss_len = (socklen_t) SUN_LEN(sa);

	/* Remove a previously bound socket existing on the filesystem. */
	ret = remove(sa->sun_path);
	if (ret != 0 && errno != ENOENT) {
		fprintf(stderr, "%s: ERROR: Failed to remove existing socket path '%s'\n",
			argv_program, sa->sun_path);
		return(false);
	}

	/* Success. */
	fprintf(stderr, "%s: INFO: Opening UNIX socket path '%s'\n",
		argv_program, sa->sun_path);
	return(true);
}

/* Setup TCP listener to receive incoming FSTRM data. */
static bool
setup_read_tcp(struct globals *ctx)
{
	int ret;

	ret = parse_port_addr(ctx->args->str_read_tcp_address, ctx->args->str_read_tcp_port,
			      &ctx->ss, &ctx->ss_len);

	if (ret == -1) {
		fprintf(stderr, "%s: ERROR: Invalid TCP listen port '%s'\n",
			argv_program, ctx->args->str_read_tcp_port);
		return(false);
	}


	if (ret == -2) {
		fprintf(stderr, "%s: ERROR: Failed to parse TCP listen address '%s'\n",
			argv_program, ctx->args->str_read_tcp_address);
		return(false);
	}

	/* Success. */
	fprintf(stderr, "%s: INFO: Opening TCP socket [%s]:%s\n",
		argv_program, ctx->args->str_read_tcp_address, ctx->args->str_read_tcp_port);

	return(true);
}

static void
init_libs(struct globals *ctx)
{
	nmsg_res res;

	nmsg_set_debug(1);
	res = nmsg_init();
	assert(res == nmsg_res_success);

	ctx->mod_dnstap = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSTAP_ID);
	if (ctx->mod_dnstap == NULL) {
		fprintf(stderr, "%s: ERROR: nmsg_msgmod_lookup(dnstap) failed\n", argv_program);
		exit(EXIT_FAILURE);
	}

	res = nmsg_msgmod_init(ctx->mod_dnstap, &ctx->clos_dnstap);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: ERROR: nmsg_msgmod_init(dnstap) failed: '%s'\n",
			argv_program, nmsg_res_lookup(res));
		exit(EXIT_FAILURE);
	}

	ctx->zmq_ctx = zmq_ctx_new();
	assert(ctx->zmq_ctx != NULL);

}

/*
 * Output can be sent to ZeroMQ endpoints and/or socket endpoints.
 * Data is mirrored to each endpoint specified via "-w" or "-s".
 */

/* Output endpoints: Array of "nmsg_output_t", which are "struct nmsg_output*" */
static nmsg_output_t *s_outputs;	/* Endpoints. */
static unsigned s_num_outputs;		/* # entries in array. */

static void __attribute__((noreturn))
fatal_errno(const char *fnc)
{
	int err = errno;

	fprintf(stderr, "%s: ERROR: %s failed, error=%d (%s)\n",
		argv_program, fnc, err, strerror(err));
	usage(NULL);
}

/* Open the endpoints for sending nmsg data. */
static void
output_open(struct globals *ctx)
{
	unsigned num_zmq, num_sock;

	num_zmq = ARGV_ARRAY_COUNT(ctx->args->w_zmq);
	num_sock = ARGV_ARRAY_COUNT(ctx->args->w_sock);

	s_outputs = my_calloc(num_zmq + num_sock, sizeof(nmsg_output_t));
	s_num_outputs = 0;

	/* Open the ZeroMQ destinations. */
	for (unsigned i = 0; i < num_zmq; i++) {
		char *zep = *ARGV_ARRAY_ENTRY_P(ctx->args->w_zmq, char*, i);
		nmsg_output_t out;

		fprintf(stderr, "%s: INFO: opening ZeroMQ endpoint '%s'\n", argv_program, zep);
		out = nmsg_output_open_zmq_endpoint(ctx->zmq_ctx, zep, NMSG_WBUFSZ_JUMBO);
		if (out == NULL) {
			fprintf(stderr, "%s: ERROR: failed to open ZeroMQ endpoint '%s'\n", argv_program, zep);
			usage(NULL);
		}

		s_outputs[s_num_outputs++] = out;
	}

	/* Open the socket-destinations. */
	for (unsigned i = 0; i < num_sock; i++) {
		char *spec = *ARGV_ARRAY_ENTRY_P(ctx->args->w_sock, char*, i);
		struct sockaddr_storage	ss;
		socklen_t salen;
		nmsg_output_t out;
		int len = 32 * 1024;
		int on = 1;
		int fd;

		fprintf(stderr, "%s: INFO: processing socket endpoint '%s'\n", argv_program, spec);

		if (!parse_sockspec(spec, &ss, &salen)) {
			fprintf(stderr, "%s: ERROR: Failed to parse socket endpoint '%s'\n", argv_program, spec);
			usage(NULL);
		}

		fd = socket(ss.ss_family, SOCK_DGRAM, 0);
		if (fd < 0)
			fatal_errno("socket()");

		if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
			fatal_errno("setsockopt(SO_BROADCAST)");

		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &len, sizeof(len)) < 0)
			fatal_errno("setsockopt(SO_SNDBUF)");

		if (connect(fd, (struct sockaddr*) &ss, salen) < 0)
			fatal_errno("connect()");

		out = nmsg_output_open_sock(fd, NMSG_WBUFSZ_JUMBO);
		if (out == NULL) {
			fprintf(stderr, "%s: ERROR: failed to open socket endpoint '%s'\n", argv_program, spec);
			usage(NULL);
		}

		s_outputs[s_num_outputs++] = out;
	}
}

/* Shutdown the output nmsg queues. */
static void
output_close(void)
{
	for (unsigned i = 0; i < s_num_outputs; i++)
		nmsg_output_close(&s_outputs[i]);
}

/* Send FSTRM payload to NMSG endpoints. */
static bool
output_write_data(const uint8_t *data, size_t data_len)
{
	struct nmsg_message *msg;
	uint8_t *data_copy;
	nmsg_res res;

	/*
	 * Create NMSG from raw payload.
	 * This takes ownership of the dynamically-allocated buffer.
	 */
	data_copy = malloc(data_len);
	if (data_copy == NULL)
		return(false);
	memcpy(data_copy, data, data_len);
	msg = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSTAP_ID,
					    data_copy, data_len, NULL);

	if (msg == NULL) {
		log_mesg(LOG_ERROR, -1, "Unable to create msg from raw payload, sz=%zu", data_len);
		free(data_copy);
		return(false);
	}

	/* Mark the internal payload to be rebuilt. */
	nmsg_message_update(msg);

	/* Send to each endpoint. */
	for (unsigned i = 0; i < s_num_outputs; i++) {
		res = nmsg_output_write(s_outputs[i], msg);

		log_mesg(LOG_WARNING, -1, "nmsg_output_write failed (%d)", res);
	}

	nmsg_message_destroy(&msg);

	return(true);
}

/*
 * Invoked when data has been received, or the client has closed the connection.
 *
 *   cd - Call-specific information
 *      - cd_reason: FS_RC_CLIENT_DATA or FS_RC_CLIENT_CLOSE
 *      - cd_ctx: The context used
 *      - cd_client: Client
 *      - cd_data: Data received (FS_RC_CLIENT_DATA)
 *      - cd_data_len: Length (bytes) of data received (FS_RC_CLIENT_DATA)
 * user - User-data supplied when callback was created
 */
static void
client_cb(struct fs_calldata *cd, void *user)
{
	struct conn *conn = user;
	struct globals *ctx = conn->ctx;

	if (cd->cd_reason == FS_RC_CLIENT_DATA) {
		log_mesg(LOG_TRACE, conn->fd, "processing data frame (%zu bytes)",
			cd->cd_data_len);

		if (!output_write_data(cd->cd_data, cd->cd_data_len)) {
			fprintf(stderr, "%s: ERROR: output_write() failed: %s\n",
				argv_program, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Accounting. */
		conn->count_read++;
		conn->bytes_read += cd->cd_data_len;

		ctx->count_written++;
		ctx->bytes_written += cd->cd_data_len;
	}

	/* Connection closed. */
	if (cd->cd_reason == FS_RC_CLIENT_CLOSE) {
		log_mesg(LOG_INFO, conn->fd, "closing (read %zu frames, %zu bytes)",
			conn->count_read, conn->bytes_read);

		conn_destroy(&conn);
	}
}

/*
 * Invoked when a client connects to the listener.
 *
 *   cd - Call-specific information
 *      - cd_reason: FS_RC_CLIENT_NEW
 *      - cd_ctx: The context used
 *      - cd_listener: The listener that received the connection
 *      - cd_client: New client created for this connection
 *      - cd_fd: fd for new client
 *      - cd_sa: sockaddr for new connection
 *      - cd_sa_len: length of cd_sa
 * user - User-data supplied when callback was created
 */
static void
listener_cb(struct fs_calldata *cd, void *user)
{
	struct globals *ctx = user;
	char ipbuf[INET6_ADDRSTRLEN];
	const struct sockaddr_in *ipv4;
	unsigned short port;

	/* Log details of new client. */
	if ((ipv4 = (const struct sockaddr_in*) cd->cd_sa) != NULL) {
		if (ipv4->sin_family == AF_INET &&
		    cd->cd_sa_len >= sizeof(struct sockaddr_in)) {
			inet_ntop(AF_INET, &ipv4->sin_addr, ipbuf, sizeof(ipbuf));
			port = ntohs(ipv4->sin_port);
			log_mesg(LOG_INFO, cd->cd_fd, "Connection from %s:%hu", ipbuf, port);
		} else if (ipv4->sin_family == AF_INET6 &&
			   cd->cd_sa_len >= sizeof(struct sockaddr_in6)) {
			const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6*) cd->cd_sa;
			inet_ntop(AF_INET6, &ipv6->sin6_addr, ipbuf, sizeof(ipbuf));
			port = ntohs(ipv6->sin6_port);
			log_mesg(LOG_INFO, cd->cd_fd, "Connection from %s:%hu", ipbuf, port);
		} else if (ipv4->sin_family == AF_UNIX) {
			log_mesg(LOG_INFO, cd->cd_fd, "Connection on UNIX socket path");
		} else {
			log_mesg(LOG_INFO, cd->cd_fd, "Connection: Unknown, family=%hu, size=%u",
				 ipv4->sin_family, cd->cd_sa_len);
		}
	}

	/* Set the callback for the new client */
	fs_client_set_callback(cd->cd_client, client_cb, conn_init(ctx, cd->cd_fd));
}

static bool
setup_event_loop(struct globals *ctx)
{
	fs_global_init(false);	/* No threading support */

	/* Create context for event-loop. */
	ctx->fsrv_ctx = fs_context_init();
	if (ctx->fsrv_ctx == NULL)
		return(false);

	/* Set the content-type for incoming connections. */
	fs_context_set_content_type(ctx->fsrv_ctx, g_program_args.str_content_type);

	/* Set high-watermark from configuration. */
	fs_context_set_highwater(ctx->fsrv_ctx, ctx->capture_highwater);

	/* Set debug level. */
	fs_context_set_debug(ctx->fsrv_ctx, g_program_args.debug);

	/* Create listener with callback invoked when new client connects. */
	ctx->fsrv_lstnr = fs_listener_add(ctx->fsrv_ctx, (struct sockaddr*) &ctx->ss, ctx->ss_len, listener_cb, ctx);
	if (ctx->fsrv_lstnr == NULL) {
		fs_context_delete(&ctx->fsrv_ctx);
		return(false);
	}

	return(true);
}

static void
shutdown_handler(int signum __attribute__((unused)))
{
	fs_context_exit(g_program_ctx.fsrv_ctx);
}

static bool
setup_signals(void)
{
	struct sigaction sa = {
		.sa_handler = shutdown_handler,
	};

	if (sigemptyset(&sa.sa_mask) != 0)
		return(false);

	if (sigaction(SIGTERM, &sa, NULL) != 0)
		return(false);
	if (sigaction(SIGINT, &sa, NULL) != 0)
		return(false);

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) != 0)
		return(false);

	return(true);
}

/* Setup input for Frame Streams data. */
static bool
setup_input(struct globals *ctx)
{
	/* UNIX socket input, if specified. */
	if (ctx->args->str_read_unix != NULL)
		return(setup_read_unix(ctx));

	if (ctx->args->str_read_tcp_address != NULL &&
	    ctx->args->str_read_tcp_port != NULL)
		/* Otherwise, TCP socket input. */
		return(setup_read_tcp(ctx));

	fprintf(stderr, "%s: ERROR: Failed to setup Frame Streams input\n", argv_program);

	return(false);
}

/* Cleanup before normal termination. */
static void
cleanup(struct globals *ctx)
{
	argv_cleanup(g_args);

	if (ctx->fsrv_lstnr != NULL)
		fs_listener_delete(&ctx->fsrv_lstnr);
	if (ctx->fsrv_ctx != NULL)
		fs_context_delete(&ctx->fsrv_ctx);

	nmsg_msgmod_fini(ctx->mod_dnstap, &ctx->clos_dnstap);

	zmq_ctx_term(&ctx->zmq_ctx);
}

int
main(int argc, char **argv)
{
	/* Parse arguments. */
	if (!parse_args(argc, argv))
		usage(NULL);

	g_program_ctx.args = &g_program_args;

	init_libs(&g_program_ctx);

	if (!setup_input(&g_program_ctx))
		usage(NULL);

	/* Open the file output. */
	output_open(&g_program_ctx);

	/* Setup signals. */
	if (!setup_signals()) {
		fprintf(stderr, "%s: ERROR: Failed to setup signals\n", argv_program);
		return(EXIT_FAILURE);
	}

	/* Setup the event loop. */
	if (!setup_event_loop(&g_program_ctx)) {
		fprintf(stderr, "%s: ERROR: Failed to setup event loop\n", argv_program);
		return(EXIT_FAILURE);
	}

	/* Run the event loop. */
	if (fs_context_run(g_program_ctx.fsrv_ctx) != 0) {
		fprintf(stderr, "%s: ERROR: Failed to start event loop\n", argv_program);
		return(EXIT_FAILURE);
	}

	fprintf(stderr, "%s: INFO: Shutting down\n", argv_program);

	/* Shut down. */
	output_close();
	cleanup(&g_program_ctx);

	/* Success. */
	return(EXIT_SUCCESS);
}

