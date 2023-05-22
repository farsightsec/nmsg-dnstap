#ifndef _FSTRM_SRV_H_
#define _FSTRM_SRV_H_

struct fs_ctx;
struct fs_listener;
struct fs_client;
struct fs_calldata;

typedef enum {
	FS_RC_CLIENT_NEW		= 1,	/* New client connection. */
	FS_RC_CLIENT_DATA		= 2,	/* Client data frame received. */
	FS_RC_CLIENT_CLOSE		= 3,	/* Client closed. */
} fs_reason_code;

/* User-supplied callback function: calldata, userdata */
typedef void (*fs_cb_func)(struct fs_calldata*, void*);

/* The "Call Data" passed with each callback. */
struct fs_calldata {
	fs_reason_code cd_reason;		/* Reason for call */
	struct fs_ctx *cd_ctx;			/* Context (opaque) */
	struct fs_listener *cd_listener;	/* Listener (opaque, for new client) */
	struct fs_client *cd_client;		/* Client (opaque) */
	unsigned char *cd_data;			/* Data */
	size_t cd_data_len;			/* Data-length (bytes) */
	const void *cd_sa;			/* New client sockaddr */
	unsigned cd_sa_len;			/* New client sockaddr size (bytes) */
	int cd_fd;				/* Client file-descriptor */
};

/*
 * One-off global initialization.
 * Arguments: Enable threading support?
 */
extern void fs_global_init(bool thread_support);

/* Create a new context for running the event-loop. */
extern struct fs_ctx *fs_context_init(void);

/* Delete a context. */
extern void fs_context_delete(struct fs_ctx **ctx);

/* Set the content-type to be used during client setup. */
extern void fs_context_set_content_type(struct fs_ctx *ctx, const char *ct);

/* Set debug-level for this context. */
extern void fs_context_set_debug(struct fs_ctx *ctx, unsigned level);

/*
 * Set the maximum frame-size collected for this context.
 * Default: Maximum frame-size collected is 256kb
 */
extern void fs_context_set_highwater(struct fs_ctx *ctx, size_t limit);

/* Run the event-loop for this context. */
extern int fs_context_run(struct fs_ctx *ctx);

/* Cause the running event-loop to exit. */
extern int fs_context_exit(struct fs_ctx *ctx);

/* Set the maximum frame-size collected for this client. */
extern void fs_client_set_callback(struct fs_client *cl, fs_cb_func cb, void *cbdata);

/*
 * Set the maximum frame-size collected for this client.
 * The initial value is taken from the context.
 */
extern void fs_client_set_highwater(struct fs_client *cl, size_t limit);

/*
 * Create a new listener.
 * The callback is invoked when a new client connects.
 */
extern struct fs_listener *fs_listener_add(struct fs_ctx *ctx, struct sockaddr *sa, unsigned sa_len, fs_cb_func cb, void *cbdata);

/* Delete a listener. */
extern void fs_listener_delete(struct fs_listener **fl);

/* Update the callback function and data for a listener. Callback function may not be NULL. */
extern void fs_listener_set_callback(struct fs_listener *fl, fs_cb_func cb, void *cbdata);

#endif

