/*
 * Copyright (c) 2014-2016, 2018 by Farsight Security, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <fstrm.h>

#include "libmy/my_alloc.h"
#include "libmy/print_string.h"

#include "fstrm_srv.h"

typedef enum {
	CONN_STATE_READING_CONTROL_READY,
	CONN_STATE_READING_CONTROL_START,
	CONN_STATE_READING_DATA,
	CONN_STATE_STOPPED,
} fs_conn_state;

typedef enum log_verbosity {
	LOG_CRITICAL		= 0,
	LOG_ERROR		= 1,
	LOG_WARNING		= 2,
	LOG_INFO		= 3,
	LOG_DEBUG		= 4,
	LOG_TRACE		= 5,
} log_verbosity;


/* Context for the event-loop. */
struct fs_ctx {
	struct event_base	*fs_base;
	char			*fs_content_type;	/* fstrm Content-Type. */
	unsigned		fs_highwater;		/* Max frame size to capture. */
	unsigned		fs_debug;		/* Debug level. */
};

/* Listener. */
struct fs_listener {
	struct fs_ctx		*fl_ctx;	/* Part of this context. */
	struct evconnlistener	*fl_listener;	/* Underlying listener. */
	fs_cb_func		fl_cb;		/* Callback for new connections. */
	void			*fl_cbdata;	/* User-data for callback. */
};

/* Client. */
struct fs_client {
	struct fs_ctx		*fc_ctx;	/* Part of this context. */
	fs_cb_func		fc_cb;		/* Callback for activity. */
	void			*fc_cbdata;	/* User-data for callback. */
	struct bufferevent	*fc_bev;	/* Buffered I/O. */
	struct fstrm_control	*fc_control;	/* Initial exchange of control messages. */
	size_t			fc_highwater;	/* Max frame-size to capture. */
	size_t			fc_bytes_skip;	/* Ignore oversized frames. */
	int			fc_fd;		/* fd for this client-connection. */
	fs_conn_state		fc_state;	/* State-machine for connection. */
};

/* Info about any (partial) frame in the incoming buffer. */
struct frame_buf_info {
	size_t fb_buf_len;	/* Length of buffer (bytes). */
 	size_t fb_frame_size;	/* Total frame length (bytes). */
 	size_t fb_payload_size;	/* Payload length (bytes). */
};

static void
srv_log(unsigned, struct fs_client*, const char*, ...) __attribute__ ((format (printf, 3, 4)));

static void
srv_log(unsigned level, struct fs_client *cl, const char *format, ...)
{
	if (level > cl->fc_ctx->fs_debug)
		return;

	fprintf(stderr, "fd=%d: ", cl->fc_fd);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fputc('\n', stderr);
}

static void
srv_log_data(unsigned, struct fs_client*, const void*, size_t, const char*, ...) __attribute__ ((format (printf, 5, 6)));

static void
srv_log_data(unsigned level, struct fs_client *cl, const void *data, size_t len, const char *format, ...)
{
	if (level > cl->fc_ctx->fs_debug)
		return;
	fprintf(stderr, "fd=%d: ", cl->fc_fd);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	print_string(data, len, stderr);
	fputc('\n', stderr);
}

/* Initialize new client; connection from specific listener. */
static struct fs_client *
client_init(struct fs_listener *fl)
{
	struct fs_client *cl;
	cl = my_calloc(1, sizeof(*cl));

	cl->fc_ctx = fl->fl_ctx;	/* Context from listener. */
	cl->fc_highwater = fl->fl_ctx->fs_highwater;
	cl->fc_state = CONN_STATE_READING_CONTROL_READY;
	cl->fc_control = fstrm_control_init();

	return(cl);
}

/* Destroy client. */
static void
client_destroy(struct fs_client *cl)
{
	fstrm_control_destroy(&cl->fc_control);
	my_free(cl);
}

/* Close the connection for a specific client. */
static void
_fc_cb_close_conn(struct bufferevent *bev, short error, void *arg)
{
	struct fs_client *cl = arg;

	/* Error detected within the libevent code. */
	if (error & BEV_EVENT_ERROR)
		srv_log(LOG_CRITICAL, cl, "libevent error: %s (%d)", strerror(errno), errno);

	srv_log(LOG_INFO, cl, "closing");

	/* There may not be a callback in place (yet). */
	if (cl->fc_cb != NULL) {
		struct fs_calldata cd = {0};

		/* Invoke callback with data. */
		cd.cd_reason = FS_RC_CLIENT_CLOSE;
		cd.cd_ctx = cl->fc_ctx;
		cd.cd_client = cl;
		cd.cd_fd = cl->fc_fd;

		cl->fc_cb(&cd, cl->fc_cbdata);
	}

	/*
	 * The BEV_OPT_CLOSE_ON_FREE flag is set on our bufferevent's, so the
	 * following call to bufferevent_free() will close the underlying
	 * socket transport.
	 */
	bufferevent_free(bev);
	client_destroy(cl);
}

/* An entire data-frame has been received. */
static void
process_data_frame(struct fs_client *cl, struct frame_buf_info *fbi)
{
	struct evbuffer *ev_input = bufferevent_get_input(cl->fc_bev);

	srv_log(LOG_TRACE, cl, "processing data frame (%zu bytes)", fbi->fb_frame_size);

	if (cl->fc_cb != NULL) {
		struct fs_calldata cd = {0};
		unsigned char *data_frame = evbuffer_pullup(ev_input, fbi->fb_frame_size);

		/* Invoke callback with data. */
		cd.cd_reason = FS_RC_CLIENT_DATA;
		cd.cd_ctx = cl->fc_ctx;
		cd.cd_client = cl;
		cd.cd_fd = cl->fc_fd;
		cd.cd_data = data_frame + 4;		/* Data (after frame size). */
		cd.cd_data_len = fbi->fb_payload_size;

		cl->fc_cb(&cd, cl->fc_cbdata);	/* Invoke callback. */
	}

	/* Delete the data frame from the input buffer. */
	evbuffer_drain(ev_input, fbi->fb_frame_size);
}

/* Send a frame to the peer. */
static bool
send_frame(struct fs_client *cl, const void *data, size_t size)
{
	srv_log_data(LOG_TRACE, cl, data, size, "writing frame (%zu) bytes: ", size);

	if (bufferevent_write(cl->fc_bev, data, size) != 0) {
		srv_log(LOG_WARNING, cl, "bufferevent_write() failed");
		return(false);
	}

	return(true);
}

/*
 * Check the remote content type against what is expected.
 * For example, for dnstap data it must be "protobuf:dnstap.Dnstap"
 */
static bool
match_content_type(struct fs_client *cl)
{
	const char *ct = cl->fc_ctx->fs_content_type;
	fstrm_res res;

	/* Match the "Content Type" against ours. */
	res = fstrm_control_match_field_content_type(cl->fc_control,
		(const uint8_t*) ct, ct ? strlen(ct) : 0);

	if (res != fstrm_res_success) {
		srv_log(LOG_WARNING, cl, "no CONTENT_TYPE matching: \"%s\"", ct ? ct : "<NULL>");
		return(false);
	}

	return(true);	/* Success. */
}

/* Write a control frame to the peer. */
static bool
write_control_frame(struct fs_client *cl)
{
	fstrm_res res;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);

	/* Encode the control frame. */
	res = fstrm_control_encode(cl->fc_control, control_frame, &len_control_frame, FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		return(false);

	/* Send the control frame. */
	fstrm_control_type type;
	fstrm_control_get_type(cl->fc_control, &type);
	srv_log(LOG_DEBUG, cl, "sending %s (%d)", fstrm_control_type_to_str(type), type);
	if (!send_frame(cl, control_frame, len_control_frame))
		return(false);

	return(true);	/* Success. */
}

static bool
process_control_frame_ready(struct fs_client *cl)
{
	const char *ct = cl->fc_ctx->fs_content_type;
	size_t n_content_type = 0;
	fstrm_res res;

	/* Retrieve the number of "Content Type" fields. */
	res = fstrm_control_get_num_field_content_type(cl->fc_control, &n_content_type);
	if (res != fstrm_res_success)
		return(false);

	for (size_t i = 0; i < n_content_type; i++) {
		const uint8_t *content_type = NULL;
		size_t len_content_type = 0;

		res = fstrm_control_get_field_content_type(cl->fc_control, i, &content_type, &len_content_type);
		if (res != fstrm_res_success)
			return(false);
		srv_log_data(LOG_TRACE, cl, content_type, len_content_type,
			     "CONTENT_TYPE [%zd/%zd] (%zd bytes): ",
			     i + 1, n_content_type, len_content_type);
	}

	/* Match the "Content Type" against ours. */
	if (!match_content_type(cl))
		return(false);

	/* Setup the ACCEPT frame. */
	fstrm_control_reset(cl->fc_control);
	res = fstrm_control_set_type(cl->fc_control, FSTRM_CONTROL_ACCEPT);
	if (res != fstrm_res_success)
		return(false);

	res = fstrm_control_add_field_content_type(cl->fc_control, (const uint8_t*) ct, ct ? strlen(ct) : 0);
	if (res != fstrm_res_success)
		return(false);

	/* Send the ACCEPT frame. */
	if (!write_control_frame(cl))
		return(false);

	/* Success. */
	cl->fc_state = CONN_STATE_READING_CONTROL_START;

	return(true);
}

static bool
process_control_frame_start(struct fs_client *cl)
{
	/* Match the "Content Type" against ours. */
	if (!match_content_type(cl))
		return(false);

	/* Success. */
	cl->fc_state = CONN_STATE_READING_DATA;
	return(true);
}

static bool
process_control_frame_stop(struct fs_client *cl)
{
	fstrm_res res;

	/* Setup the FINISH frame. */
	fstrm_control_reset(cl->fc_control);
	res = fstrm_control_set_type(cl->fc_control, FSTRM_CONTROL_FINISH);
	if (res != fstrm_res_success)
		return(false);

	/* Send the FINISH frame. */
	if (!write_control_frame(cl))
		return(false);

	cl->fc_state = CONN_STATE_STOPPED;

	/*
	 * We return(true) here, which prevents the caller from closing
	 * the connection directly (with the FINISH frame still in our
	 * write buffer). The connection will be closed after the FINISH
	 * frame is written and the write callback (cb_write) is called
	 * to refill the write buffer.
	 */
	return(true);
}

/* Process any control-frame received. */
static bool
process_control_frame(struct fs_client *cl)
{
	fstrm_res res;
	fstrm_control_type type;

	/* Get the control frame type. */
	res = fstrm_control_get_type(cl->fc_control, &type);
	if (res != fstrm_res_success)
		return(false);

	srv_log(LOG_DEBUG, cl, "received %s (%u)", fstrm_control_type_to_str(type), type);

	switch (cl->fc_state) {
	case CONN_STATE_READING_CONTROL_READY:
		if (type != FSTRM_CONTROL_READY)
			return(false);
		return(process_control_frame_ready(cl));

	case CONN_STATE_READING_CONTROL_START:
		if (type != FSTRM_CONTROL_START)
			return(false);
		return(process_control_frame_start(cl));

	case CONN_STATE_READING_DATA:
		if (type != FSTRM_CONTROL_STOP)
			return(false);
		return(process_control_frame_stop(cl));

	default:
		return(false);
	}

	return(true);	/* Success. */
}

/* Extract a control-frame from the incoming stream. */
static bool
load_control_frame(struct fs_client *cl, struct frame_buf_info *fbi)
{
	struct evbuffer *ev_input = bufferevent_get_input(cl->fc_bev);
	fstrm_res res;
	unsigned char *control_frame;

	/* Check if the frame is too big. */
	if (fbi->fb_frame_size >= FSTRM_CONTROL_FRAME_LENGTH_MAX)
		return(false);		/* Malformed. */

	/* Get a pointer to the full, linearized control frame. */
	control_frame = evbuffer_pullup(ev_input, fbi->fb_frame_size);
	if (control_frame == NULL)
		return(false);		/* Malformed. */

	srv_log_data(LOG_TRACE, cl, control_frame, fbi->fb_frame_size,
		     "reading control frame (%zu bytes): ", fbi->fb_frame_size);

	/* Decode the control frame. */
	res = fstrm_control_decode(cl->fc_control, control_frame, fbi->fb_frame_size, FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		return(false);		/* Malformed. */

	/* Drain the data read. */
	evbuffer_drain(ev_input, fbi->fb_frame_size);

	return(true);			/* Success. */
}

/* Incoming buffer have enough data for an entire frame? */
static bool
can_read_full_frame(struct fs_client *cl, struct frame_buf_info *fbi)
{
	struct evbuffer *ev_input = bufferevent_get_input(cl->fc_bev);
	uint32_t tmp[2] = {0};

	/*
	 * This tracks the total number of bytes that must be removed from the
	 * input buffer to read the entire frame.
	 */
	fbi->fb_frame_size = 0;

	/* Check if the frame length field has fully arrived. */
	if (fbi->fb_buf_len < sizeof(uint32_t))
		return(false);

	/* Read the frame length field (leave data in buffer). */
	evbuffer_copyout(ev_input, &tmp[0], sizeof(uint32_t));
	fbi->fb_payload_size = ntohl(tmp[0]);

	/* Account for the frame length field. */
	fbi->fb_frame_size += sizeof(uint32_t);

	/* Account for the length of the frame payload. */
	fbi->fb_frame_size += fbi->fb_payload_size;

	/* Check if this is a control frame. */
	if (fbi->fb_payload_size == 0) {
		uint32_t len_control_frame = 0;

		/*
		 * Check if the control frame length field has fully arrived.
		 * Note that the input buffer hasn't been drained, so we also
		 * need to account for the initial frame length field. That is,
		 * there must be at least 8 bytes available in the buffer.
		 */
		if (fbi->fb_buf_len < 2 * sizeof(uint32_t))
			return(false);

		/* Read the control frame length. */
		evbuffer_copyout(ev_input, &tmp[0], 2 * sizeof(uint32_t));
		len_control_frame = ntohl(tmp[1]);

		/* Account for the length of the control frame length field. */
		fbi->fb_frame_size += sizeof(uint32_t);

		/* Enforce minimum and maximum control frame size. */
		if (len_control_frame < sizeof(uint32_t) || len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX)
		{
			_fc_cb_close_conn(cl->fc_bev, 0, cl);
			return(false);
		}

		/* Account for the control frame length. */
		fbi->fb_frame_size += len_control_frame;
	}

	/*
	 * Check if the frame has fully arrived. 'fb_buf_len' must have at least
	 * the number of bytes needed in order to read the full frame, which is
	 * exactly 'fb_frame_size'.
	 */
	if (fbi->fb_buf_len < fbi->fb_frame_size) {
		srv_log(LOG_TRACE, cl, "incomplete message (have %zu bytes, want %zu)", fbi->fb_buf_len, fbi->fb_frame_size);
		if (fbi->fb_frame_size > cl->fc_highwater) {
			srv_log(LOG_WARNING, cl, "Skipping %zu byte message (%zu buffer)", fbi->fb_frame_size, cl->fc_highwater);
			cl->fc_bytes_skip = fbi->fb_frame_size;
		}
		return(false);
	}

	/* Success. The entire frame can now be read from the buffer. */
	return(true);
}

/* Invoked when buffer can accept data for sending to client. */
static void
_fc_cb_write(struct bufferevent *bev, void *arg)
{
	struct fs_client *cl = arg;

	if (cl->fc_state != CONN_STATE_STOPPED)
		return;

	_fc_cb_close_conn(bev, 0, cl);
}

/* Perform any one-off global initialization. */
void
fs_global_init(bool thread_support)
{
	static unsigned once = 0;

	if (once == 0) {
		once++;
		if (thread_support)
			evthread_use_pthreads();
	}
}

/* Initialize a new context to be used with an event-loop. */
struct fs_ctx *
fs_context_init(void)
{
	struct fs_ctx *ctx = my_calloc(1, sizeof(*ctx));

	ctx->fs_base = event_base_new();
	if (ctx->fs_base == NULL) {
		my_free(ctx);
		return(NULL);
	}

	ctx->fs_highwater = 256 * 1024;	/* Max frame-size collected. */

	return(ctx);
}

/* Delete a context. */
void
fs_context_delete(struct fs_ctx **ctx)
{
	struct fs_ctx *c = *ctx;

	*ctx = NULL;

	my_free(c->fs_content_type);
	event_base_free(c->fs_base);
	my_free(c);
}

/* Run the event-loop for a context. */
int
fs_context_run(struct fs_ctx *ctx)
{
	return(event_base_dispatch(ctx->fs_base));
}

/* Signal the event-loop for a context to exit. */
int
fs_context_exit(struct fs_ctx *ctx)
{
	return(event_base_loopexit(ctx->fs_base, NULL));
}

/* Set the wanted content-type for connections. */
void
fs_context_set_content_type(struct fs_ctx *ctx, const char *ct)
{
	my_free(ctx->fs_content_type);
	ctx->fs_content_type = ct ? my_strdup(ct) : NULL;
}

void
fs_context_set_debug(struct fs_ctx *ctx, unsigned level)
{
	ctx->fs_debug = level;
}

/* Sets max frame-size captured for this context. */
void
fs_context_set_highwater(struct fs_ctx *ctx, size_t limit)
{
	ctx->fs_highwater = limit;
}

/* Set the callback function and user-data used for a listener. */
void
fs_listener_set_callback(struct fs_listener *fl, fs_cb_func cb, void *cbdata)
{
	if (cb != NULL)
		fl->fl_cb = cb;
	fl->fl_cbdata = cbdata;
}

/* Set the callback function and user-data used for a client. */
void
fs_client_set_callback(struct fs_client *cl, fs_cb_func cb, void *cbdata)
{
	cl->fc_cb = cb;
	cl->fc_cbdata = cbdata;
	if (cl->fc_cb != NULL)
		bufferevent_enable(cl->fc_bev, EV_READ | EV_WRITE);
	else
		bufferevent_disable(cl->fc_bev, EV_READ | EV_WRITE);
}

/* Sets max frame-size captured for this client. */
void
fs_client_set_highwater(struct fs_client *cl, size_t limit)
{
	cl->fc_highwater = limit;
}

/* Read-callback for client. */
static void
_fc_cb_read(struct bufferevent *bev, void *arg)
{
	struct fs_client *cl = arg;
	struct evbuffer *ev_input;
	struct frame_buf_info fbi = {0};

	assert(cl->fc_bev == bev);

	ev_input = bufferevent_get_input(bev);

	for (;;) {
		/* Get the number of bytes available in the buffer. */
		fbi.fb_buf_len = evbuffer_get_length(ev_input);

		/* Check if there is any data available in the buffer. */
		if (fbi.fb_buf_len <= 0)
			return;

		/* Check if the full frame has arrived. */
		if ((cl->fc_bytes_skip == 0) && !can_read_full_frame(cl, &fbi))
			return;

		/* Skip bytes of oversized frames. */
		if (cl->fc_bytes_skip > 0) {
			size_t skip = cl->fc_bytes_skip;

			if (skip > fbi.fb_buf_len)
				skip = fbi.fb_buf_len;

			srv_log(LOG_TRACE, cl, "Skipping %zu bytes", skip);
			evbuffer_drain(ev_input, skip);
			cl->fc_bytes_skip -= skip;
			continue;
		}

		/* Process the frame. */
		if (fbi.fb_payload_size > 0) {
			/* This is a data frame. */
			process_data_frame(cl, &fbi);
		} else {
			/* This is a control frame. */

			if (!load_control_frame(cl, &fbi)) {
				/* Malformed control frame, shut down the connection. */
				_fc_cb_close_conn(bev, 0, cl);
				return;
			}

			if (!process_control_frame(cl)) {
				/*
				 * Invalid control state requested, or the
				 * end-of-stream has been reached. Shut down
				 * the connection.
				 */
				_fc_cb_close_conn(bev, 0, cl);
				return;
			}
		}
	}
}

/* Callback for any error detected on the listener. */
static void
_fl_cb_accept_error(struct evconnlistener *listener __attribute__((unused)),
		    void *arg __attribute__((unused)))
{
	int err = EVUTIL_SOCKET_ERROR();

	fprintf(stderr, "accept() failed: %d/%s\n",
		err, evutil_socket_error_to_string(err));
}

/* Internal callback to accept a new client-connection. Does setup, then invokes user callback. */
static void
_fl_cb_accept_conn(struct evconnlistener *listener, evutil_socket_t fd,
		   struct sockaddr *sa, int socklen, void *arg)
{
	struct fs_listener *fl = arg;		/* Accept on this listener. */
	struct fs_ctx *ctx = fl->fl_ctx;	/* Context of listener. */
	struct fs_client *fc;
	struct fs_calldata cd = {0};
	struct bufferevent *bev;

	assert(fl->fl_listener == listener);

	/* Setup new client. */
	fc = client_init(fl);
	if (fc == NULL) {
		evutil_closesocket(fd);
		return;
	}

	/* Create the bufferevent to handle data for this client. */
	bev = bufferevent_socket_new(ctx->fs_base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (bev == NULL) {
		client_destroy(fc);
		evutil_closesocket(fd);
		return;
	}

	fc->fc_bev = bev;
	fc->fc_fd = (int) bufferevent_getfd(bev);

	/* Invoke callback advising of new connection. */
	cd.cd_reason = FS_RC_CLIENT_NEW;
	cd.cd_ctx = ctx;
	cd.cd_listener = fl;		/* Listener involved. */
	cd.cd_client = fc;		/* New opaque client object. */
	cd.cd_fd = fc->fc_fd;		/* "fd" for new client connection. */
	cd.cd_sa = sa;			/* Details of client. */
	cd.cd_sa_len = socklen;

	fl->fl_cb(&cd, fl->fl_cbdata);	/* Invoke callback. */

	bufferevent_setcb(bev, _fc_cb_read, _fc_cb_write, _fc_cb_close_conn, fc);
	bufferevent_setwatermark(bev, EV_READ, 0, fc->fc_highwater);

	/* Enable this client if there is a callback in place. */
	if (fc->fc_cb != NULL)
		bufferevent_enable(bev, EV_READ | EV_WRITE);
}

/*
 * Add a new listener to a context.
 * Specifies the connection point, and callback-details for a new connection.
 *
 *    ctx - Listener created within this context.
 *     sa - Details of listener.
 * sa_len - Size (bytes) of sa above.
 *     cb - Callback function to invoke for new client.
 * cbdata - User-data for callback function.
 */
struct fs_listener *
fs_listener_add(struct fs_ctx *ctx, struct sockaddr *sa, unsigned sa_len, fs_cb_func cb, void *cbdata)
{
	struct fs_listener *fl;

	if (cb == NULL)		/* Must have a callback function. */
		return(NULL);

	fl = my_calloc(1, sizeof(*fl));

	fl->fl_ctx = ctx;

	/* Set the callback function and user-data. */
	fl->fl_cb = cb;
	fl->fl_cbdata = cbdata;

	/* Create the evconnlistener. */
	unsigned flags = 0;
	flags |= LEV_OPT_CLOSE_ON_FREE;	/* Closes underlying sockets. */
	flags |= LEV_OPT_CLOSE_ON_EXEC;	/* Sets FD_CLOEXEC on underlying fd's. */
	flags |= LEV_OPT_REUSEABLE;	/* Sets SO_REUSEADDR on listener. */

	fl->fl_listener = evconnlistener_new_bind(ctx->fs_base, _fl_cb_accept_conn, (void*) fl, flags, -1, sa, sa_len);

	if (fl->fl_listener == NULL) {
		my_free(fl);
		return(NULL);
	}

	evconnlistener_set_error_cb(fl->fl_listener, _fl_cb_accept_error);

	return(fl);
}

/* Delete a listener. */
void
fs_listener_delete(struct fs_listener **fl)
{
	struct fs_listener *f = *fl;

	*fl = NULL;

	evconnlistener_free(f->fl_listener);
	my_free(f);
}

