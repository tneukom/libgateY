/*
 * libwebsockets amalgated source (http://jsoncpp.sourceforge.net/).
 */

/***************************************************
 * external/libwebsockets/src/lws_config.h
 ***************************************************/

/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 to use CyaSSL as a replacement for OpenSSL. 
 * LWS_OPENSSL_SUPPORT needs to be set also for this to work. */
/* #undef USE_CYASSL */

/* The Libwebsocket version */
#define LWS_LIBRARY_VERSION "1.3"

/* The current git commit hash that we're building from */
/* #undef LWS_BUILD_HASH */

/* Build with OpenSSL support */
/* #undef LWS_OPENSSL_SUPPORT */

/* The client should load and trust CA root certs it finds in the OS */
#define LWS_SSL_CLIENT_USE_OS_CA_CERTS

/* Sets the path where the client certs should be installed. */
#define LWS_OPENSSL_CLIENT_CERTS "../share"

/* Turn off websocket extensions */
#define LWS_NO_EXTENSIONS

/* Enable libev io loop */
/* #undef LWS_USE_LIBEV */

/* Build with support for ipv6 */
/* #undef LWS_USE_IPV6 */

/* Build with support for HTTP2 */
/* #undef LWS_USE_HTTP2 */

/* Turn on latency measuring code */
/* #undef LWS_LATENCY */

/* Don't build the daemonizeation api */
#define LWS_NO_DAEMONIZE

/* Build without server support */
/* #undef LWS_NO_SERVER */

/* Build without client support */
#define LWS_NO_CLIENT

/* If we should compile with MinGW support */
/* #undef LWS_MINGW_SUPPORT */

/* Use the BSD getifaddrs that comes with libwebsocket, for uclibc support */
//#define LWS_BUILTIN_GETIFADDRS

/* Define to 1 if you have the `bzero' function. */
/* #undef HAVE_BZERO */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the <fcntl.h> header file. */
//#define HAVE_FCNTL_H

/* Define to 1 if you have the `fork' function. */
/* #undef HAVE_FORK */

/* Define to 1 if you have the `getenv’ function. */
#define HAVE_GETENV

/* Define to 1 if you have the <in6addr.h> header file. */
/* #undef HAVE_IN6ADDR_H */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H

/* Define to 1 if you have the `ssl' library (-lssl). */
/* #undef HAVE_LIBSSL */

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC

/* Define to 1 if you have the `socket' function. */
/* #undef HAVE_SOCKET */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H

/* Define to 1 if you have the <sys/prctl.h> header file. */
/* #undef HAVE_SYS_PRCTL_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Define to 1 if you have the `vfork' function. */
/* #undef HAVE_VFORK */

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK

/* Define to 1 if you have the <zlib.h> header file. */
/* #undef HAVE_ZLIB_H */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#undef LT_OBJDIR // We're not using libtool

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS

/* Version number of package */
#define VERSION

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
//#define pid_t

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to 1 if we have getifaddrs */
/* #undef HAVE_GETIFADDRS */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
/***************************************************
 * external/libwebsockets/src/platforms.h
 ***************************************************/

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996) //'strcpy': This function or variable may be unsafe. 
#pragma warning(disable: 4244) // '=' : conversion from 'unsigned short' to 'unsigned char', possible loss of data
#pragma warning(disable: 4018) // '<' : signed/unsigned mismatch
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#ifndef GATEY_IS_AMALGAMATION
#include "libwebsockets.h"
#endif
/***************************************************
 * external/libwebsockets/src/private-libwebsockets.h
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

/* System introspection configs */
//#ifdef CMAKE_BUILD
#ifndef WEBSOCKET_IS_AMALGAMATION
#include "lws_config.h"
#endif
//#else
//#if defined(WIN32) || defined(_WIN32)
//#define inline __inline
//#else /* not WIN32 */
//#include "config.h"

//#endif /* not WIN32 */
//#endif /* not CMAKE */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if defined(WIN32) || defined(_WIN32)
#define LWS_NO_DAEMONIZE
#define LWS_ERRNO WSAGetLastError()
#define LWS_EAGAIN WSAEWOULDBLOCK
#define LWS_EALREADY WSAEALREADY
#define LWS_EINPROGRESS WSAEINPROGRESS
#define LWS_EINTR WSAEINTR
#define LWS_EISCONN WSAEISCONN
#define LWS_EWOULDBLOCK WSAEWOULDBLOCK
#define LWS_POLLHUP (FD_CLOSE)
#define LWS_POLLIN (FD_READ | FD_ACCEPT)
#define LWS_POLLOUT (FD_WRITE)
#define MSG_NOSIGNAL 0
#define SHUT_RDWR SD_BOTH
#define SOL_TCP IPPROTO_TCP

#define compatible_close(fd) closesocket(fd)
#define compatible_file_close(fd) CloseHandle(fd)
#define compatible_file_seek_cur(fd, offset) SetFilePointer(fd, offset, NULL, FILE_CURRENT)
#define compatible_file_read(amount, fd, buf, len) {\
	DWORD _amount; \
	if (!ReadFile(fd, buf, len, &_amount, NULL)) \
		amount = -1; \
	else \
		amount = _amount; \
	}
#define lws_set_blocking_send(wsi) wsi->sock_send_blocking = TRUE
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <in6addr.h>
#include <mstcpip.h>

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32_WCE
#define vsnprintf _vsnprintf
#endif

#define LWS_INVALID_FILE INVALID_HANDLE_VALUE
#else /* not windows --> */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef LWS_BUILTIN_GETIFADDRS
 #include <getifaddrs.h>
#else
 #include <ifaddrs.h>
#endif
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#ifndef LWS_NO_FORK
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#ifdef LWS_USE_LIBEV
#include <ev.h>
#endif /* LWS_USE_LIBEV */

#include <sys/mman.h>
#include <sys/time.h>

#define LWS_ERRNO errno
#define LWS_EAGAIN EAGAIN
#define LWS_EALREADY EALREADY
#define LWS_EINPROGRESS EINPROGRESS
#define LWS_EINTR EINTR
#define LWS_EISCONN EISCONN
#define LWS_EWOULDBLOCK EWOULDBLOCK
#define LWS_INVALID_FILE -1
#define LWS_POLLHUP (POLLHUP|POLLERR)
#define LWS_POLLIN (POLLIN)
#define LWS_POLLOUT (POLLOUT)
#define compatible_close(fd) close(fd)
#define compatible_file_close(fd) close(fd)
#define compatible_file_seek_cur(fd, offset) lseek(fd, offset, SEEK_CUR)
#define compatible_file_read(amount, fd, buf, len) \
		amount = read(fd, buf, len);
#define lws_set_blocking_send(wsi)
#endif

#ifndef HAVE_BZERO
#define bzero(b, len) (memset((b), '\0', (len)), (void) 0)
#endif

#ifndef HAVE_STRERROR
#define strerror(x) ""
#endif

#ifdef LWS_OPENSSL_SUPPORT
#ifdef USE_CYASSL
#include <cyassl/openssl/ssl.h>
#include <cyassl/error.h>
unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md);
#else
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif /* not USE_CYASSL */
#endif

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "libwebsockets.h"
#endif

#if defined(WIN32) || defined(_WIN32)

#ifndef BIG_ENDIAN
#define BIG_ENDIAN    4321  /* to show byte order (taken from gcc) */
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
typedef unsigned __int64 u_int64_t;

#undef __P
#ifndef __P
#if __STDC__
#define __P(protos) protos
#else
#define __P(protos) ()
#endif
#endif

#else

#include <sys/stat.h>
#include <sys/cdefs.h>
#include <sys/time.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#elif defined(__linux__)
#include <endian.h>
#endif

#if !defined(BYTE_ORDER)
# define BYTE_ORDER __BYTE_ORDER
#endif
#if !defined(LITTLE_ENDIAN)
# define LITTLE_ENDIAN __LITTLE_ENDIAN
#endif
#if !defined(BIG_ENDIAN)
# define BIG_ENDIAN __BIG_ENDIAN
#endif

#endif

/*
 * Mac OSX as well as iOS do not define the MSG_NOSIGNAL flag,
 * but happily have something equivalent in the SO_NOSIGPIPE flag.
 */
#ifdef __APPLE__
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#ifndef LWS_MAX_HEADER_LEN
#define LWS_MAX_HEADER_LEN 1024
#endif
#ifndef LWS_MAX_PROTOCOLS
#define LWS_MAX_PROTOCOLS 5
#endif
#ifndef LWS_MAX_EXTENSIONS_ACTIVE
#define LWS_MAX_EXTENSIONS_ACTIVE 3
#endif
#ifndef SPEC_LATEST_SUPPORTED
#define SPEC_LATEST_SUPPORTED 13
#endif
#ifndef AWAITING_TIMEOUT
#define AWAITING_TIMEOUT 5
#endif
#ifndef CIPHERS_LIST_STRING
#define CIPHERS_LIST_STRING "DEFAULT"
#endif
#ifndef LWS_SOMAXCONN
#define LWS_SOMAXCONN SOMAXCONN
#endif

#define MAX_WEBSOCKET_04_KEY_LEN 128
#define LWS_MAX_SOCKET_IO_BUF 4096

#ifndef SYSTEM_RANDOM_FILEPATH
#define SYSTEM_RANDOM_FILEPATH "/dev/urandom"
#endif
#ifndef LWS_MAX_ZLIB_CONN_BUFFER
#define LWS_MAX_ZLIB_CONN_BUFFER (64 * 1024)
#endif

/*
 * if not in a connection storm, check for incoming
 * connections this many normal connection services
 */
#define LWS_LISTEN_SERVICE_MODULO 10

enum lws_websocket_opcodes_07 {
	LWS_WS_OPCODE_07__CONTINUATION = 0,
	LWS_WS_OPCODE_07__TEXT_FRAME = 1,
	LWS_WS_OPCODE_07__BINARY_FRAME = 2,

	LWS_WS_OPCODE_07__NOSPEC__MUX = 7,

	/* control extensions 8+ */

	LWS_WS_OPCODE_07__CLOSE = 8,
	LWS_WS_OPCODE_07__PING = 9,
	LWS_WS_OPCODE_07__PONG = 0xa,
};


enum lws_connection_states {
	WSI_STATE_HTTP,
	WSI_STATE_HTTP_ISSUING_FILE,
	WSI_STATE_HTTP_HEADERS,
	WSI_STATE_HTTP_BODY,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED,
	WSI_STATE_CLIENT_UNCONNECTED,
	WSI_STATE_RETURNED_CLOSE_ALREADY,
	WSI_STATE_AWAITING_CLOSE_ACK,
	WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE,
};

enum lws_rx_parse_state {
	LWS_RXPS_NEW,

	LWS_RXPS_04_MASK_NONCE_1,
	LWS_RXPS_04_MASK_NONCE_2,
	LWS_RXPS_04_MASK_NONCE_3,

	LWS_RXPS_04_FRAME_HDR_1,
	LWS_RXPS_04_FRAME_HDR_LEN,
	LWS_RXPS_04_FRAME_HDR_LEN16_2,
	LWS_RXPS_04_FRAME_HDR_LEN16_1,
	LWS_RXPS_04_FRAME_HDR_LEN64_8,
	LWS_RXPS_04_FRAME_HDR_LEN64_7,
	LWS_RXPS_04_FRAME_HDR_LEN64_6,
	LWS_RXPS_04_FRAME_HDR_LEN64_5,
	LWS_RXPS_04_FRAME_HDR_LEN64_4,
	LWS_RXPS_04_FRAME_HDR_LEN64_3,
	LWS_RXPS_04_FRAME_HDR_LEN64_2,
	LWS_RXPS_04_FRAME_HDR_LEN64_1,

	LWS_RXPS_07_COLLECT_FRAME_KEY_1,
	LWS_RXPS_07_COLLECT_FRAME_KEY_2,
	LWS_RXPS_07_COLLECT_FRAME_KEY_3,
	LWS_RXPS_07_COLLECT_FRAME_KEY_4,

	LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED
};


enum connection_mode {
	LWS_CONNMODE_HTTP_SERVING,
	LWS_CONNMODE_HTTP_SERVING_ACCEPTED, /* actual HTTP service going on */
	LWS_CONNMODE_PRE_WS_SERVING_ACCEPT,

	LWS_CONNMODE_WS_SERVING,
	LWS_CONNMODE_WS_CLIENT,

	/* transient, ssl delay hiding */
	LWS_CONNMODE_SSL_ACK_PENDING,

	/* transient modes */
	LWS_CONNMODE_WS_CLIENT_WAITING_CONNECT,
	LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY,
	LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE,
	LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE2,
	LWS_CONNMODE_WS_CLIENT_WAITING_SSL,
	LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY,
	LWS_CONNMODE_WS_CLIENT_WAITING_EXTENSION_CONNECT,
	LWS_CONNMODE_WS_CLIENT_PENDING_CANDIDATE_CHILD,

	/* special internal types */
	LWS_CONNMODE_SERVER_LISTENER,
};

enum {
	LWS_RXFLOW_ALLOW = (1 << 0),
	LWS_RXFLOW_PENDING_CHANGE = (1 << 1),
};

struct libwebsocket_protocols;
struct libwebsocket;

#ifdef LWS_USE_LIBEV
struct lws_io_watcher {
	struct ev_io watcher;
	struct libwebsocket_context* context;
};

struct lws_signal_watcher {
	struct ev_signal watcher;
	struct libwebsocket_context* context;
};
#endif /* LWS_USE_LIBEV */

struct libwebsocket_context {
#ifdef _WIN32
	WSAEVENT *events;
#endif
	struct libwebsocket_pollfd *fds;
	struct libwebsocket **lws_lookup; /* fd to wsi */
	int fds_count;
#ifdef LWS_USE_LIBEV
	struct ev_loop* io_loop;
	struct lws_io_watcher w_accept;
	struct lws_signal_watcher w_sigint;
#endif /* LWS_USE_LIBEV */
	int max_fds;
	int listen_port;
	const char *iface;
	char http_proxy_address[128];
	char canonical_hostname[128];
	unsigned int http_proxy_port;
	unsigned int options;
	time_t last_timeout_check_s;

	/*
	 * usable by anything in the service code, but only if the scope
	 * does not last longer than the service action (since next service
	 * of any socket can likewise use it and overwrite)
	 */
	unsigned char service_buffer[LWS_MAX_SOCKET_IO_BUF];

	int started_with_parent;

	int fd_random;
	int listen_service_modulo;
	int listen_service_count;
	int listen_service_fd;
	int listen_service_extraseen;

	/*
	 * set to the Thread ID that's doing the service loop just before entry
	 * to poll indicates service thread likely idling in poll()
	 * volatile because other threads may check it as part of processing
	 * for pollfd event change.
	 */
	volatile int service_tid;
#ifndef _WIN32
	int dummy_pipe_fds[2];
#endif

	int ka_time;
	int ka_probes;
	int ka_interval;

#ifdef LWS_LATENCY
	unsigned long worst_latency;
	char worst_latency_info[256];
#endif

#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	int allow_non_ssl_on_ssl_port;
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_client_ctx;
#endif
	struct libwebsocket_protocols *protocols;
	int count_protocols;
#ifndef LWS_NO_EXTENSIONS
	struct libwebsocket_extension *extensions;
#endif
    struct lws_token_limits *token_limits;
	void *user_space;
};

enum {
	LWS_EV_READ = (1 << 0),
	LWS_EV_WRITE = (1 << 1),
	LWS_EV_START = (1 << 2),
	LWS_EV_STOP = (1 << 3),
};

#ifdef LWS_USE_LIBEV
#define LWS_LIBEV_ENABLED(context) (context->options & LWS_SERVER_OPTION_LIBEV)
LWS_EXTERN void lws_feature_status_libev(struct lws_context_creation_info *info);
LWS_EXTERN void
lws_libev_accept(struct libwebsocket_context *context,
		 struct libwebsocket *new_wsi, int accept_fd);
LWS_EXTERN void
lws_libev_io(struct libwebsocket_context *context,
				struct libwebsocket *wsi, int flags);
LWS_EXTERN int
lws_libev_init_fd_table(struct libwebsocket_context *context);
LWS_EXTERN void
lws_libev_run(struct libwebsocket_context *context);
#else
#define LWS_LIBEV_ENABLED(context) (0)
#define lws_feature_status_libev(_a) \
			lwsl_notice("libev support not compiled in\n")
#define lws_libev_accept(_a, _b, _c) ((void) 0)
#define lws_libev_io(_a, _b, _c) ((void) 0)
#define lws_libev_init_fd_table(_a) (0)
#define lws_libev_run(_a) ((void) 0)
#endif

#ifdef LWS_USE_IPV6
#define LWS_IPV6_ENABLED(context) (!(context->options & LWS_SERVER_OPTION_DISABLE_IPV6))
#else
#define LWS_IPV6_ENABLED(context) (0)
#endif

enum uri_path_states {
	URIPS_IDLE,
	URIPS_SEEN_SLASH,
	URIPS_SEEN_SLASH_DOT,
	URIPS_SEEN_SLASH_DOT_DOT,
	URIPS_ARGUMENTS,
};

enum uri_esc_states {
	URIES_IDLE,
	URIES_SEEN_PERCENT,
	URIES_SEEN_PERCENT_H1,
};

/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration; the user can use the pointer with
 * other APIs to get information out of it.
 */

struct lws_fragments {
	unsigned short offset;
	unsigned short len;
	unsigned char next_frag_index;
};

struct allocated_headers {
	unsigned short next_frag_index;
	unsigned short pos;
	unsigned char frag_index[WSI_TOKEN_COUNT];
	struct lws_fragments frags[WSI_TOKEN_COUNT * 2];
	char data[LWS_MAX_HEADER_LEN];
#ifndef LWS_NO_CLIENT
	char initial_handshake_hash_base64[30];
	unsigned short c_port;
#endif
};

struct _lws_http_mode_related {
	struct allocated_headers *ah; /* mirroring  _lws_header_related */
#if defined(WIN32) || defined(_WIN32)
	HANDLE fd;
#else
	int fd;
#endif
	unsigned long filepos;
	unsigned long filelen;

	int content_length;
	int content_length_seen;
	int body_index;
	unsigned char *post_buffer;
};

struct _lws_header_related {
	struct allocated_headers *ah;
	short lextable_pos;
	unsigned short current_token_limit;
	unsigned char parser_state; /* enum lws_token_indexes */
	enum uri_path_states ups;
	enum uri_esc_states ues;
	char esc_stash;
};

struct _lws_websocket_related {
	char *rx_user_buffer;
	int rx_user_buffer_head;
	unsigned char frame_masking_nonce_04[4];
	unsigned char frame_mask_index;
	size_t rx_packet_length;
	unsigned char opcode;
	unsigned int final:1;
	unsigned char rsv;
	unsigned int frame_is_binary:1;
	unsigned int all_zero_nonce:1;
	short close_reason; /* enum lws_close_status */
	unsigned char *rxflow_buffer;
	int rxflow_len;
	int rxflow_pos;
	unsigned int rxflow_change_to:2;
	unsigned int this_frame_masked:1;
	unsigned int inside_frame:1; /* next write will be more of frame */
	unsigned int clean_buffer:1; /* buffer not rewritten by extension */
};

struct libwebsocket {

	/* lifetime members */

#ifdef LWS_USE_LIBEV
    struct lws_io_watcher w_read;
    struct lws_io_watcher w_write;
#endif /* LWS_USE_LIBEV */
	const struct libwebsocket_protocols *protocol;
#ifndef LWS_NO_EXTENSIONS
	struct libwebsocket_extension *
				   active_extensions[LWS_MAX_EXTENSIONS_ACTIVE];
	void *active_extensions_user[LWS_MAX_EXTENSIONS_ACTIVE];
	unsigned char count_active_extensions;
	unsigned int extension_data_pending:1;
#endif
	unsigned char ietf_spec_revision;

	char mode; /* enum connection_mode */
	char state; /* enum lws_connection_states */
	char lws_rx_parse_state; /* enum lws_rx_parse_state */
	char rx_frame_type; /* enum libwebsocket_write_protocol */

	unsigned int hdr_parsing_completed:1;
	unsigned int user_space_externally_allocated:1;

	char pending_timeout; /* enum pending_timeout */
	time_t pending_timeout_limit;

	int sock;
	int position_in_fds_table;
#ifdef LWS_LATENCY
	unsigned long action_start;
	unsigned long latency_start;
#endif

	/* truncated send handling */
	unsigned char *truncated_send_malloc; /* non-NULL means buffering in progress */
	unsigned int truncated_send_allocation; /* size of malloc */
	unsigned int truncated_send_offset; /* where we are in terms of spilling */
	unsigned int truncated_send_len; /* how much is buffered */

	void *user_space;

	/* members with mutually exclusive lifetimes are unionized */

	union u {
		struct _lws_http_mode_related http;
		struct _lws_header_related hdr;
		struct _lws_websocket_related ws;
	} u;

#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
	BIO *client_bio;
	unsigned int use_ssl:2;
#endif

#ifdef _WIN32
	BOOL sock_send_blocking;
#endif
};

LWS_EXTERN int log_level;

LWS_EXTERN void
libwebsocket_close_and_free_session(struct libwebsocket_context *context,
			       struct libwebsocket *wsi, enum lws_close_status);

LWS_EXTERN int
remove_wsi_socket_from_fds(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);

#ifndef LWS_LATENCY
static inline void lws_latency(struct libwebsocket_context *context,
		struct libwebsocket *wsi, const char *action,
					 int ret, int completion) { while (0); }
static inline void lws_latency_pre(struct libwebsocket_context *context,
					struct libwebsocket *wsi) { while (0); }
#else
#define lws_latency_pre(_context, _wsi) lws_latency(_context, _wsi, NULL, 0, 0)
extern void
lws_latency(struct libwebsocket_context *context,
			struct libwebsocket *wsi, const char *action,
						       int ret, int completion);
#endif

LWS_EXTERN int
libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c);

LWS_EXTERN int
libwebsocket_parse(struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char c);

LWS_EXTERN int
lws_b64_selftest(void);

LWS_EXTERN struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *context, int fd);

LWS_EXTERN int
insert_wsi_socket_into_fds(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);

LWS_EXTERN int
lws_issue_raw(struct libwebsocket *wsi, unsigned char *buf, size_t len);


LWS_EXTERN int
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				    struct libwebsocket *wsi, unsigned int sec);

LWS_EXTERN struct libwebsocket *
libwebsocket_client_connect_2(struct libwebsocket_context *context,
	struct libwebsocket *wsi);

LWS_EXTERN struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context);

LWS_EXTERN char *
libwebsockets_generate_client_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi, char *pkt);

LWS_EXTERN int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
			      struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd);
/*
 * EXTENSIONS
 */

#ifndef LWS_NO_EXTENSIONS
LWS_VISIBLE void
lws_context_init_extensions(struct lws_context_creation_info *info,
				    struct libwebsocket_context *context);
LWS_EXTERN int
lws_any_extension_handled(struct libwebsocket_context *context,
			  struct libwebsocket *wsi,
			  enum libwebsocket_extension_callback_reasons r,
			  void *v, size_t len);

LWS_EXTERN int
lws_ext_callback_for_each_active(struct libwebsocket *wsi, int reason,
						    void *buf, int len);
LWS_EXTERN int
lws_ext_callback_for_each_extension_type(
		struct libwebsocket_context *context, struct libwebsocket *wsi,
			int reason, void *arg, int len);
#else
#define lws_any_extension_handled(_a, _b, _c, _d, _e) (0)
#define lws_ext_callback_for_each_active(_a, _b, _c, _d) (0)
#define lws_ext_callback_for_each_extension_type(_a, _b, _c, _d, _e) (0)
#define lws_issue_raw_ext_access lws_issue_raw
#define lws_context_init_extensions(_a, _b)
#endif

LWS_EXTERN int
lws_client_interpret_server_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi);

LWS_EXTERN int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c);

LWS_EXTERN int
lws_issue_raw_ext_access(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);

LWS_EXTERN int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi);

LWS_EXTERN int
user_callback_handle_rxflow(callback_function,
		struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);

LWS_EXTERN int
lws_plat_set_socket_options(struct libwebsocket_context *context, int fd);

LWS_EXTERN int
lws_allocate_header_table(struct libwebsocket *wsi);

LWS_EXTERN char *
lws_hdr_simple_ptr(struct libwebsocket *wsi, enum lws_token_indexes h);

LWS_EXTERN int
lws_hdr_simple_create(struct libwebsocket *wsi,
				enum lws_token_indexes h, const char *s);

LWS_EXTERN int
libwebsocket_ensure_user_space(struct libwebsocket *wsi);

LWS_EXTERN int
lws_change_pollfd(struct libwebsocket *wsi, int _and, int _or);

#ifndef LWS_NO_SERVER
int lws_context_init_server(struct lws_context_creation_info *info,
			    struct libwebsocket_context *context);
LWS_EXTERN int handshake_0405(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);
LWS_EXTERN int
libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);
LWS_EXTERN void
lws_server_get_canonical_hostname(struct libwebsocket_context *context,
				struct lws_context_creation_info *info);
#else
#define lws_context_init_server(_a, _b) (0)
#define libwebsocket_interpret_incoming_packet(_a, _b, _c) (0)
#define lws_server_get_canonical_hostname(_a, _b)
#endif

#ifndef LWS_NO_DAEMONIZE
LWS_EXTERN int get_daemonize_pid();
#else
#define get_daemonize_pid() (0)
#endif

LWS_EXTERN int interface_to_sa(struct libwebsocket_context *context,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen);

LWS_EXTERN void lwsl_emit_stderr(int level, const char *line);

#ifdef _WIN32
LWS_EXTERN HANDLE lws_plat_open_file(const char* filename, unsigned long* filelen);
#else
LWS_EXTERN int lws_plat_open_file(const char* filename, unsigned long* filelen);
#endif

enum lws_ssl_capable_status {
	LWS_SSL_CAPABLE_ERROR = -1,
	LWS_SSL_CAPABLE_MORE_SERVICE = -2,
};

#ifndef LWS_OPENSSL_SUPPORT
#define LWS_SSL_ENABLED(context) (0)
unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md);
#define lws_context_init_server_ssl(_a, _b) (0)
#define lws_ssl_destroy(_a)
#define lws_context_init_http2_ssl(_a)
#define lws_ssl_pending(_a) (0)
#define lws_ssl_capable_read lws_ssl_capable_read_no_ssl
#define lws_ssl_capable_write lws_ssl_capable_write_no_ssl
#define lws_server_socket_service_ssl(_a, _b, _c, _d, _e) (0)
#define lws_ssl_close(_a) (0)
#define lws_ssl_context_destroy(_a)
#else
#define LWS_SSL_ENABLED(context) (context->use_ssl)
LWS_EXTERN int lws_ssl_pending(struct libwebsocket *wsi);
LWS_EXTERN int openssl_websocket_private_data_index;
LWS_EXTERN int
lws_ssl_capable_read(struct libwebsocket *wsi, unsigned char *buf, int len);

LWS_EXTERN int
lws_ssl_capable_write(struct libwebsocket *wsi, unsigned char *buf, int len);
LWS_EXTERN int
lws_server_socket_service_ssl(struct libwebsocket_context *context,
		struct libwebsocket **wsi, struct libwebsocket *new_wsi,
		int accept_fd, struct libwebsocket_pollfd *pollfd);
LWS_EXTERN int
lws_ssl_close(struct libwebsocket *wsi);
LWS_EXTERN void
lws_ssl_context_destroy(struct libwebsocket_context *context);
#ifndef LWS_NO_SERVER
LWS_EXTERN int
lws_context_init_server_ssl(struct lws_context_creation_info *info,
		     struct libwebsocket_context *context);
#else
#define lws_context_init_server_ssl(_a, _b) (0)
#endif
LWS_EXTERN void
lws_ssl_destroy(struct libwebsocket_context *context);

/* HTTP2-related */

#ifdef LWS_USE_HTTP2
LWS_EXTERN void
lws_context_init_http2_ssl(struct libwebsocket_context *context);
#else
#define lws_context_init_http2_ssl(_a)
#endif
#endif

LWS_EXTERN int
lws_ssl_capable_read_no_ssl(struct libwebsocket *wsi, unsigned char *buf, int len);

LWS_EXTERN int
lws_ssl_capable_write_no_ssl(struct libwebsocket *wsi, unsigned char *buf, int len);

#ifndef LWS_NO_CLIENT
	LWS_EXTERN int lws_client_socket_service(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd);
#ifdef LWS_OPENSSL_SUPPORT
	LWS_EXTERN int lws_context_init_client_ssl(struct lws_context_creation_info *info,
			    struct libwebsocket_context *context);
#else
	#define lws_context_init_client_ssl(_a, _b) (0)
#endif
	LWS_EXTERN int lws_handshake_client(struct libwebsocket *wsi, unsigned char **buf, size_t len);
	LWS_EXTERN void
	libwebsockets_decode_ssl_error(void);
#else
#define lws_context_init_client_ssl(_a, _b) (0)
#define lws_handshake_client(_a, _b, _c) (0)
#endif
#ifndef LWS_NO_SERVER
	LWS_EXTERN int lws_server_socket_service(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd);
	LWS_EXTERN int _libwebsocket_rx_flow_control(struct libwebsocket *wsi);
	LWS_EXTERN int lws_handshake_server(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char **buf, size_t len);
#else
#define lws_server_socket_service(_a, _b, _c) (0)
#define _libwebsocket_rx_flow_control(_a) (0)
#define lws_handshake_server(_a, _b, _c, _d) (0)
#endif

/*
 * lws_plat_
 */
LWS_EXTERN void
lws_plat_delete_socket_from_fds(struct libwebsocket_context *context,
					       struct libwebsocket *wsi, int m);
LWS_EXTERN void
lws_plat_insert_socket_into_fds(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);
LWS_EXTERN void
lws_plat_service_periodic(struct libwebsocket_context *context);

LWS_EXTERN int
lws_plat_change_pollfd(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, struct libwebsocket_pollfd *pfd);
LWS_EXTERN int
lws_plat_context_early_init(void);
LWS_EXTERN void
lws_plat_context_early_destroy(struct libwebsocket_context *context);
LWS_EXTERN void
lws_plat_context_late_destroy(struct libwebsocket_context *context);
LWS_EXTERN int
lws_poll_listen_fd(struct libwebsocket_pollfd *fd);
LWS_EXTERN int
lws_plat_service(struct libwebsocket_context *context, int timeout_ms);
LWS_EXTERN int
lws_plat_init_fd_tables(struct libwebsocket_context *context);
LWS_EXTERN void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info);
LWS_EXTERN unsigned long long
time_in_microseconds(void);
LWS_EXTERN const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt);

/***************************************************
 * external/libwebsockets/src/base64-decode.cpp
 ***************************************************/

/*
 * This code originally came from here
 *
 * http://base64.sourceforge.net/b64.c
 *
 * with the following license:
 *
 * LICENCE:        Copyright (c) 2001 Bob Trower, Trantor Standard Systems Inc.
 *
 *                Permission is hereby granted, free of charge, to any person
 *                obtaining a copy of this software and associated
 *                documentation files (the "Software"), to deal in the
 *                Software without restriction, including without limitation
 *                the rights to use, copy, modify, merge, publish, distribute,
 *                sublicense, and/or sell copies of the Software, and to
 *                permit persons to whom the Software is furnished to do so,
 *                subject to the following conditions:
 *
 *                The above copyright notice and this permission notice shall
 *                be included in all copies or substantial portions of the
 *                Software.
 *
 *                THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 *                KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *                WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 *                PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 *                OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *                OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 *                OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *                SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * VERSION HISTORY:
 *               Bob Trower 08/04/01 -- Create Version 0.00.00B
 *
 * I cleaned it up quite a bit to match the (linux kernel) style of the rest
 * of libwebsockets; this version is under LGPL2 like the rest of libwebsockets
 * since he explictly allows sublicensing, but I give the URL above so you can
 * get the original with Bob's super-liberal terms directly if you prefer.
 */


#include <stdio.h>
#include <string.h>

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

static const char encode[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz0123456789+/";
static const char decode[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW"
			     "$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

LWS_VISIBLE int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size)
{
	unsigned char triple[3];
	int i;
	int len;
	int line = 0;
	int done = 0;

	while (in_len) {
		len = 0;
		for (i = 0; i < 3; i++) {
			if (in_len) {
				triple[i] = *in++;
				len++;
				in_len--;
			} else
				triple[i] = 0;
		}
		if (!len)
			continue;

		if (done + 4 >= out_size)
			return -1;

		*out++ = encode[triple[0] >> 2];
		*out++ = encode[((triple[0] & 0x03) << 4) |
					     ((triple[1] & 0xf0) >> 4)];
		*out++ = (len > 1 ? encode[((triple[1] & 0x0f) << 2) |
					     ((triple[2] & 0xc0) >> 6)] : '=');
		*out++ = (len > 2 ? encode[triple[2] & 0x3f] : '=');

		done += 4;
		line += 4;
	}

	if (done + 1 >= out_size)
		return -1;

	*out++ = '\0';

	return done;
}

/***************************************************
 * external/libwebsockets/src/context.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

#ifndef LWS_BUILD_HASH
#define LWS_BUILD_HASH "unknown-build-hash"
#endif

static const char *library_version = LWS_LIBRARY_VERSION " " LWS_BUILD_HASH;

/**
 * lws_get_library_version: get version and git hash library built from
 *
 *	returns a const char * to a string like "1.1 178d78c"
 *	representing the library version followed by the git head hash it
 *	was built from
 */

LWS_VISIBLE const char *
lws_get_library_version(void)
{
	return library_version;
}

/**
 * libwebsocket_create_context() - Create the websocket handler
 * @info:	pointer to struct with parameters
 *
 *	This function creates the listening socket (if serving) and takes care
 *	of all initialization in one step.
 *
 *	After initialization, it returns a struct libwebsocket_context * that
 *	represents this server.  After calling, user code needs to take care
 *	of calling libwebsocket_service() with the context pointer to get the
 *	server's sockets serviced.  This must be done in the same process
 *	context as the initialization call.
 *
 *	The protocol callback functions are called for a handful of events
 *	including http requests coming in, websocket connections becoming
 *	established, and data arriving; it's also called periodically to allow
 *	async transmission.
 *
 *	HTTP requests are sent always to the FIRST protocol in @protocol, since
 *	at that time websocket protocol has not been negotiated.  Other
 *	protocols after the first one never see any HTTP callack activity.
 *
 *	The server created is a simple http server by default; part of the
 *	websocket standard is upgrading this http connection to a websocket one.
 *
 *	This allows the same server to provide files like scripts and favicon /
 *	images or whatever over http and dynamic data over websockets all in
 *	one place; they're all handled in the user callback.
 */

LWS_VISIBLE struct libwebsocket_context *
libwebsocket_create_context(struct lws_context_creation_info *info)
{
	struct libwebsocket_context *context = NULL;
	char *p;

	int pid_daemon = get_daemonize_pid();

	lwsl_notice("Initial logging level %d\n", log_level);
	lwsl_notice("Library version: %s\n", library_version);
#ifdef LWS_USE_IPV6
	if (!(info->options & LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_notice("IPV6 compiled in and enabled\n");
	else
		lwsl_notice("IPV6 compiled in but disabled\n");
#else
	lwsl_notice("IPV6 not compiled in\n");
#endif
	lws_feature_status_libev(info);
	lwsl_info(" LWS_MAX_HEADER_LEN: %u\n", LWS_MAX_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS: %u\n", LWS_MAX_PROTOCOLS);

	lwsl_info(" SPEC_LATEST_SUPPORTED: %u\n", SPEC_LATEST_SUPPORTED);
	lwsl_info(" AWAITING_TIMEOUT: %u\n", AWAITING_TIMEOUT);
	lwsl_info(" SYSTEM_RANDOM_FILEPATH: '%s'\n", SYSTEM_RANDOM_FILEPATH);
	lwsl_info(" LWS_MAX_ZLIB_CONN_BUFFER: %u\n", LWS_MAX_ZLIB_CONN_BUFFER);

	if (lws_plat_context_early_init())
		return NULL;

	context = (struct libwebsocket_context *)
				malloc(sizeof(struct libwebsocket_context));
	if (!context) {
		lwsl_err("No memory for websocket context\n");
		return NULL;
	}
	memset(context, 0, sizeof(*context));

	if (pid_daemon) {
		context->started_with_parent = pid_daemon;
		lwsl_notice(" Started with daemon pid %d\n", pid_daemon);
	}

	context->listen_service_extraseen = 0;
	context->protocols = info->protocols;
	context->token_limits = info->token_limits;
	context->listen_port = info->port;
	context->http_proxy_port = 0;
	context->http_proxy_address[0] = '\0';
	context->options = info->options;
	context->iface = info->iface;
	/* to reduce this allocation, */
	context->max_fds = getdtablesize();
	lwsl_notice(" static allocation: %u + (%u x %u fds) = %u bytes\n",
		sizeof(struct libwebsocket_context),
		sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *),
		context->max_fds,
		sizeof(struct libwebsocket_context) +
		((sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *)) *
							     context->max_fds));

	context->fds = (struct libwebsocket_pollfd *)
				malloc(sizeof(struct libwebsocket_pollfd) *
							      context->max_fds);
	if (context->fds == NULL) {
		lwsl_err("Unable to allocate fds array for %d connections\n",
							      context->max_fds);
		free(context);
		return NULL;
	}

	context->lws_lookup = (struct libwebsocket **)
		      malloc(sizeof(struct libwebsocket *) * context->max_fds);
	if (context->lws_lookup == NULL) {
		lwsl_err(
		  "Unable to allocate lws_lookup array for %d connections\n",
							      context->max_fds);
		free(context->fds);
		free(context);
		return NULL;
	}
	memset(context->lws_lookup, 0, sizeof(struct libwebsocket *) *
							context->max_fds);

	if (lws_plat_init_fd_tables(context)) {
		free(context->lws_lookup);
		free(context->fds);
		free(context);
		return NULL;
	}

	lws_context_init_extensions(info, context);

	context->user_space = info->user;

	strcpy(context->canonical_hostname, "unknown");

	lws_server_get_canonical_hostname(context, info);

	/* split the proxy ads:port if given */

	if (info->http_proxy_address) {
		strncpy(context->http_proxy_address, info->http_proxy_address,
				      sizeof(context->http_proxy_address) - 1);
		context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';
		context->http_proxy_port = info->http_proxy_port;
	} else {
#ifdef HAVE_GETENV
		p = getenv("http_proxy");
		if (p) {
			strncpy(context->http_proxy_address, p,
				       sizeof(context->http_proxy_address) - 1);
			context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';

			p = strchr(context->http_proxy_address, ':');
			if (p == NULL) {
				lwsl_err("http_proxy needs to be ads:port\n");
				goto bail;
			}
			*p = '\0';
			context->http_proxy_port = atoi(p + 1);
		}
#endif
	}

	if (context->http_proxy_address[0])
		lwsl_notice(" Proxy %s:%u\n",
				context->http_proxy_address,
						      context->http_proxy_port);

	lwsl_notice(
		" per-conn mem: %u + %u headers + protocol rx buf\n",
				sizeof(struct libwebsocket),
					      sizeof(struct allocated_headers));
		
	if (lws_context_init_server_ssl(info, context))
		goto bail;
	
	if (lws_context_init_client_ssl(info, context))
		goto bail;

	if (lws_context_init_server(info, context))
		goto bail;

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
	lws_plat_drop_app_privileges(info);

	/* initialize supported protocols */

	for (context->count_protocols = 0;
		info->protocols[context->count_protocols].callback;
						   context->count_protocols++) {

		lwsl_parser("  Protocol: %s\n",
				info->protocols[context->count_protocols].name);

		info->protocols[context->count_protocols].owning_server =
									context;
		info->protocols[context->count_protocols].protocol_index =
						       context->count_protocols;

		/*
		 * inform all the protocols that they are doing their one-time
		 * initialization if they want to
		 */
		info->protocols[context->count_protocols].callback(context,
			       NULL, LWS_CALLBACK_PROTOCOL_INIT, NULL, NULL, 0);
	}

	/*
	 * give all extensions a chance to create any per-context
	 * allocations they need
	 */

	if (info->port != CONTEXT_PORT_NO_LISTEN) {
		if (lws_ext_callback_for_each_extension_type(context, NULL,
				LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT,
								   NULL, 0) < 0)
			goto bail;
	} else
		if (lws_ext_callback_for_each_extension_type(context, NULL,
				LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT,
								   NULL, 0) < 0)
			goto bail;

	return context;

bail:
	libwebsocket_context_destroy(context);
	return NULL;
}

/**
 * libwebsocket_context_destroy() - Destroy the websocket context
 * @context:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
LWS_VISIBLE void
libwebsocket_context_destroy(struct libwebsocket_context *context)
{
	int n;
	struct libwebsocket_protocols *protocol = context->protocols;

	lwsl_notice("%s\n", __func__);

#ifdef LWS_LATENCY
	if (context->worst_latency_info[0])
		lwsl_notice("Worst latency: %s\n", context->worst_latency_info);
#endif

	for (n = 0; n < context->fds_count; n++) {
		struct libwebsocket *wsi =
					context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		libwebsocket_close_and_free_session(context,
			wsi, LWS_CLOSE_STATUS_NOSTATUS /* no protocol close */);
		n--;
	}

	/*
	 * give all extensions a chance to clean up any per-context
	 * allocations they might have made
	 */
	if (context->listen_port) {
		if (lws_ext_callback_for_each_extension_type(context, NULL,
			 LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT, NULL, 0) < 0)
			return;
	} else
		if (lws_ext_callback_for_each_extension_type(context, NULL,
			 LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT, NULL, 0) < 0)
			return;

	/*
	 * inform all the protocols that they are done and will have no more
	 * callbacks
	 */

	while (protocol->callback) {
		protocol->callback(context, NULL, LWS_CALLBACK_PROTOCOL_DESTROY,
				NULL, NULL, 0);
		protocol++;
	}

	lws_plat_context_early_destroy(context);

	lws_ssl_context_destroy(context);

	if (context->fds)
		free(context->fds);
	if (context->lws_lookup)
		free(context->lws_lookup);

	lws_plat_context_late_destroy(context);

	free(context);
}

/***************************************************
 * external/libwebsockets/src/handshake.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

/*
 * -04 of the protocol (actually the 80th version) has a radically different
 * handshake.  The 04 spec gives the following idea
 *
 *    The handshake from the client looks as follows:
 *
 *      GET /chat HTTP/1.1
 *      Host: server.example.com
 *      Upgrade: websocket
 *      Connection: Upgrade
 *      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
 *      Sec-WebSocket-Origin: http://example.com
 *      Sec-WebSocket-Protocol: chat, superchat
 *	Sec-WebSocket-Version: 4
 *
 *  The handshake from the server looks as follows:
 *
 *       HTTP/1.1 101 Switching Protocols
 *       Upgrade: websocket
 *       Connection: Upgrade
 *       Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
 *       Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
 *       Sec-WebSocket-Protocol: chat
 */

/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 */

LWS_VISIBLE int
libwebsocket_read(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char *buf, size_t len)
{
	size_t n;

	switch (wsi->state) {

	case WSI_STATE_HTTP_BODY:
http_postbody:
		while (len--) {

			if (wsi->u.http.content_length_seen >= wsi->u.http.content_length)
				break;

			wsi->u.http.post_buffer[wsi->u.http.body_index++] = *buf++;
			wsi->u.http.content_length_seen++;
			n = wsi->protocol->rx_buffer_size;
			if (!n)
				n = LWS_MAX_SOCKET_IO_BUF;

			if (wsi->u.http.body_index != n &&
			    wsi->u.http.content_length_seen != wsi->u.http.content_length)
				continue;

			if (wsi->protocol->callback) {
				n = wsi->protocol->callback(
					wsi->protocol->owning_server, wsi,
					    LWS_CALLBACK_HTTP_BODY,
					    wsi->user_space, wsi->u.http.post_buffer,
							wsi->u.http.body_index);
				wsi->u.http.body_index = 0;
				if (n)
					goto bail;
			}

			if (wsi->u.http.content_length_seen == wsi->u.http.content_length) {
				/* he sent the content in time */
				libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
				n = wsi->protocol->callback(
					wsi->protocol->owning_server, wsi,
					    LWS_CALLBACK_HTTP_BODY_COMPLETION,
					    wsi->user_space, NULL, 0);
				wsi->u.http.body_index = 0;
				if (n)
					goto bail;
			}

		}

		/* 
		 * we need to spill here so everything is seen in the case
		 * there is no content-length
		 */
		if (wsi->u.http.body_index && wsi->protocol->callback) {
			n = wsi->protocol->callback(
				wsi->protocol->owning_server, wsi,
				    LWS_CALLBACK_HTTP_BODY,
				    wsi->user_space, wsi->u.http.post_buffer,
						wsi->u.http.body_index);
			wsi->u.http.body_index = 0;
			if (n)
				goto bail;
		}
		break;

	case WSI_STATE_HTTP_ISSUING_FILE:
	case WSI_STATE_HTTP:
		wsi->state = WSI_STATE_HTTP_HEADERS;
		wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
		wsi->u.hdr.lextable_pos = 0;
		/* fallthru */
	case WSI_STATE_HTTP_HEADERS:

		lwsl_parser("issuing %d bytes to parser\n", (int)len);

		if (lws_handshake_client(wsi, &buf, len))
			goto bail;

		switch (lws_handshake_server(context, wsi, &buf, len)) {
		case 1:
			goto bail;
		case 2:
			goto http_postbody;
		}
		break;

	case WSI_STATE_AWAITING_CLOSE_ACK:
	case WSI_STATE_ESTABLISHED:
		if (lws_handshake_client(wsi, &buf, len))
			goto bail;
		switch (wsi->mode) {
		case LWS_CONNMODE_WS_SERVING:

			if (libwebsocket_interpret_incoming_packet(wsi, buf, len) < 0) {
				lwsl_info("interpret_incoming_packet has bailed\n");
				goto bail;
			}
			break;
		}
		break;
	default:
		lwsl_err("libwebsocket_read: Unhandled state\n");
		break;
	}

	return 0;

bail:
	lwsl_debug("closing connection at libwebsocket_read bail:\n");

	libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);

	return -1;
}

/***************************************************
 * external/libwebsockets/src/libwebsockets.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

int log_level = LLL_ERR | LLL_WARN | LLL_NOTICE;
static void (*lwsl_emit)(int level, const char *line) = lwsl_emit_stderr;

static const char * const log_level_names[] = {
	"ERR",
	"WARN",
	"NOTICE",
	"INFO",
	"DEBUG",
	"PARSER",
	"HEADER",
	"EXTENSION",
	"CLIENT",
	"LATENCY",
};


void
libwebsocket_close_and_free_session(struct libwebsocket_context *context,
			 struct libwebsocket *wsi, enum lws_close_status reason)
{
	int n, m, ret;
	int old_state;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 2 +
						  LWS_SEND_BUFFER_POST_PADDING];
	struct lws_tokens eff_buf;

	if (!wsi)
		return;

	old_state = wsi->state;

	switch (old_state) {
	case WSI_STATE_DEAD_SOCKET:
		return;

	/* we tried the polite way... */
	case WSI_STATE_AWAITING_CLOSE_ACK:
		goto just_kill_connection;

	case WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE:
		if (wsi->truncated_send_len) {
			libwebsocket_callback_on_writable(context, wsi);
			return;
		}
		lwsl_info("wsi %p completed WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE\n", wsi);
		goto just_kill_connection;
	default:
		if (wsi->truncated_send_len) {
			lwsl_info("wsi %p entering WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE\n", wsi);
			wsi->state = WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE;
			return;
		}
		break;
	}

	wsi->u.ws.close_reason = reason;

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT_WAITING_CONNECT ||
			wsi->mode == LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE) {

		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLIENT_CONNECTION_ERROR, NULL, NULL, 0);

		free(wsi->u.hdr.ah);
		goto just_kill_connection;
	}

	if (wsi->mode == LWS_CONNMODE_HTTP_SERVING_ACCEPTED) {
		if (wsi->u.http.post_buffer) {
			free(wsi->u.http.post_buffer);
			wsi->u.http.post_buffer = NULL;
		}
		if (wsi->u.http.fd != LWS_INVALID_FILE) {
			lwsl_debug("closing http file\n");
			compatible_file_close(wsi->u.http.fd);
			wsi->u.http.fd = LWS_INVALID_FILE;
			context->protocols[0].callback(context, wsi,
				LWS_CALLBACK_CLOSED_HTTP, wsi->user_space, NULL, 0);
		}
	}

	/*
	 * are his extensions okay with him closing?  Eg he might be a mux
	 * parent and just his ch1 aspect is closing?
	 */
	
	if (lws_ext_callback_for_each_active(wsi,
		      LWS_EXT_CALLBACK_CHECK_OK_TO_REALLY_CLOSE, NULL, 0) > 0) {
		lwsl_ext("extension vetoed close\n");
		return;
	}

	/*
	 * flush any tx pending from extensions, since we may send close packet
	 * if there are problems with send, just nuke the connection
	 */

	do {
		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* show every extension the new incoming data */

		m = lws_ext_callback_for_each_active(wsi,
			  LWS_EXT_CALLBACK_FLUSH_PENDING_TX, &eff_buf, 0);
		if (m < 0) {
			lwsl_ext("Extension reports fatal error\n");
			goto just_kill_connection;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len)
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
				      eff_buf.token_len) != eff_buf.token_len) {
				lwsl_debug("close: ext spill failed\n");
				goto just_kill_connection;
			}
	} while (ret);

	/*
	 * signal we are closing, libsocket_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * WSI_STATE_RETURNED_CLOSE_ALREADY and we will skip this.
	 *
	 * Likewise if it's a second call to close this connection after we
	 * sent the close indication to the peer already, we are in state
	 * WSI_STATE_AWAITING_CLOSE_ACK and will skip doing this a second time.
	 */

	if (old_state == WSI_STATE_ESTABLISHED &&
					  reason != LWS_CLOSE_STATUS_NOSTATUS) {

		lwsl_debug("sending close indication...\n");

		/* make valgrind happy */
		memset(buf, 0, sizeof(buf));
		n = libwebsocket_write(wsi,
				&buf[LWS_SEND_BUFFER_PRE_PADDING + 2],
							    0, LWS_WRITE_CLOSE);
		if (n >= 0) {
			/*
			 * we have sent a nice protocol level indication we
			 * now wish to close, we should not send anything more
			 */

			wsi->state = WSI_STATE_AWAITING_CLOSE_ACK;

			/*
			 * ...and we should wait for a reply for a bit
			 * out of politeness
			 */

			libwebsocket_set_timeout(wsi,
						  PENDING_TIMEOUT_CLOSE_ACK, 1);

			lwsl_debug("sent close indication, awaiting ack\n");

			return;
		}

		lwsl_info("close: sending close packet failed, hanging up\n");

		/* else, the send failed and we should just hang up */
	}

just_kill_connection:

	lwsl_debug("close: just_kill_connection\n");

	/*
	 * we won't be servicing or receiving anything further from this guy
	 * delete socket from the internal poll list if still present
	 */

	remove_wsi_socket_from_fds(context, wsi);

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if ((old_state == WSI_STATE_ESTABLISHED ||
	     wsi->mode == LWS_CONNMODE_WS_SERVING ||
	     wsi->mode == LWS_CONNMODE_WS_CLIENT)) {

		if (wsi->u.ws.rx_user_buffer) {
			free(wsi->u.ws.rx_user_buffer);
			wsi->u.ws.rx_user_buffer = NULL;
		}
		if (wsi->u.ws.rxflow_buffer) {
			free(wsi->u.ws.rxflow_buffer);
			wsi->u.ws.rxflow_buffer = NULL;
		}
		if (wsi->truncated_send_malloc) {
			/* not going to be completed... nuke it */
			free(wsi->truncated_send_malloc);
			wsi->truncated_send_malloc = NULL;
			wsi->truncated_send_len = 0;
		}
	}

	/* tell the user it's all over for this guy */

	if (wsi->protocol && wsi->protocol->callback &&
			((old_state == WSI_STATE_ESTABLISHED) ||
			 (old_state == WSI_STATE_RETURNED_CLOSE_ALREADY) ||
			 (old_state == WSI_STATE_AWAITING_CLOSE_ACK))) {
		lwsl_debug("calling back CLOSED\n");
		wsi->protocol->callback(context, wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);
	} else if (wsi->mode == LWS_CONNMODE_HTTP_SERVING_ACCEPTED) {
		lwsl_debug("calling back CLOSED_HTTP\n");
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLOSED_HTTP, wsi->user_space, NULL, 0 );
	} else
		lwsl_debug("not calling back closed\n");

	/* deallocate any active extension contexts */
	
	if (lws_ext_callback_for_each_active(wsi, LWS_EXT_CALLBACK_DESTROY, NULL, 0) < 0)
		lwsl_warn("extension destruction failed\n");
#ifndef LWS_NO_EXTENSIONS
	for (n = 0; n < wsi->count_active_extensions; n++)
		free(wsi->active_extensions_user[n]);
#endif
	/*
	 * inform all extensions in case they tracked this guy out of band
	 * even though not active on him specifically
	 */
	if (lws_ext_callback_for_each_extension_type(context, wsi,
		       LWS_EXT_CALLBACK_DESTROY_ANY_WSI_CLOSING, NULL, 0) < 0)
		lwsl_warn("ext destroy wsi failed\n");

/*	lwsl_info("closing fd=%d\n", wsi->sock); */

	if (!lws_ssl_close(wsi) && wsi->sock >= 0) {
		n = shutdown(wsi->sock, SHUT_RDWR);
		if (n)
			lwsl_debug("closing: shutdown ret %d\n", LWS_ERRNO);

		n = compatible_close(wsi->sock);
		if (n)
			lwsl_debug("closing: close ret %d\n", LWS_ERRNO);
	}

	/* outermost destroy notification for wsi (user_space still intact) */
	context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_WSI_DESTROY, wsi->user_space, NULL, 0);

	if (wsi->protocol && wsi->protocol->per_session_data_size &&
	    wsi->user_space && !wsi->user_space_externally_allocated)
		free(wsi->user_space);

	free(wsi);
}

/**
 * libwebsockets_get_peer_addresses() - Get client address information
 * @context:	Libwebsockets context
 * @wsi:	Local struct libwebsocket associated with
 * @fd:		Connection socket descriptor
 * @name:	Buffer to take client address name
 * @name_len:	Length of client address name buffer
 * @rip:	Buffer to take client address IP qotted quad
 * @rip_len:	Length of client address IP buffer
 *
 *	This function fills in @name and @rip with the name and IP of
 *	the client connected with socket descriptor @fd.  Names may be
 *	truncated if there is not enough room.  If either cannot be
 *	determined, they will be returned as valid zero-length strings.
 */

LWS_VISIBLE void
libwebsockets_get_peer_addresses(struct libwebsocket_context *context,
	struct libwebsocket *wsi, int fd, char *name, int name_len,
					char *rip, int rip_len)
{
	socklen_t len;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin4;
	struct hostent *host;
	struct hostent *host1;
	char ip[128];
	unsigned char *p;
	int n;
#ifdef AF_LOCAL
	struct sockaddr_un *un;
#endif
	int ret = -1;

	rip[0] = '\0';
	name[0] = '\0';

	lws_latency_pre(context, wsi);

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {

		len = sizeof(sin6);
		if (getpeername(fd, (struct sockaddr *) &sin6, &len) < 0) {
			lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}

		if (!lws_plat_inet_ntop(AF_INET6, &sin6.sin6_addr, rip, rip_len)) {
			lwsl_err("inet_ntop", strerror(LWS_ERRNO));
			goto bail;
		}

		// Strip off the IPv4 to IPv6 header if one exists
		if (strncmp(rip, "::ffff:", 7) == 0)
			memmove(rip, rip + 7, strlen(rip) - 6);

		getnameinfo((struct sockaddr *)&sin6,
				sizeof(struct sockaddr_in6), name,
							name_len, NULL, 0, 0);

	} else
#endif
	{
		len = sizeof(sin4);
		if (getpeername(fd, (struct sockaddr *) &sin4, &len) < 0) {
			lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}
		host = gethostbyaddr((char *) &sin4.sin_addr,
						sizeof(sin4.sin_addr), AF_INET);
		if (host == NULL) {
			lwsl_warn("gethostbyaddr: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}

		strncpy(name, host->h_name, name_len);
		name[name_len - 1] = '\0';

		host1 = gethostbyname(host->h_name);
		if (host1 == NULL)
			goto bail;
		p = (unsigned char *)host1;
		n = 0;
		while (p != NULL) {
			p = (unsigned char *)host1->h_addr_list[n++];
			if (p == NULL)
				continue;
			if ((host1->h_addrtype != AF_INET)
#ifdef AF_LOCAL
				&& (host1->h_addrtype != AF_LOCAL)
#endif
				)
				continue;

			if (host1->h_addrtype == AF_INET)
				sprintf(ip, "%u.%u.%u.%u",
						p[0], p[1], p[2], p[3]);
#ifdef AF_LOCAL
			else {
				un = (struct sockaddr_un *)p;
				strncpy(ip, un->sun_path, sizeof(ip) - 1);
				ip[sizeof(ip) - 1] = '\0';
			}
#endif
			p = NULL;
			strncpy(rip, ip, rip_len);
			rip[rip_len - 1] = '\0';
		}
	}

	ret = 0;
bail:
	lws_latency(context, wsi, "libwebsockets_get_peer_addresses", ret, 1);
}



/**
 * libwebsocket_context_user() - get the user data associated with the context
 * @context: Websocket context
 *
 *	This returns the optional user allocation that can be attached to
 *	the context the sockets live in at context_create time.  It's a way
 *	to let all sockets serviced in the same context share data without
 *	using globals statics in the user code.
 */
LWS_EXTERN void *
libwebsocket_context_user(struct libwebsocket_context *context)
{
	return context->user_space;
}


/**
 * libwebsocket_callback_all_protocol() - Callback all connections using
 *				the given protocol with the given reason
 *
 * @protocol:	Protocol whose connections will get callbacks
 * @reason:	Callback reason index
 */

LWS_VISIBLE int
libwebsocket_callback_all_protocol(
		const struct libwebsocket_protocols *protocol, int reason)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			protocol->callback(context, wsi,
			(libwebsocket_callback_reasons)reason, wsi->user_space, NULL, 0);
	}

	return 0;
}

/**
 * libwebsocket_set_timeout() - marks the wsi as subject to a timeout
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 * @reason:	timeout reason
 * @secs:	how many seconds
 */

LWS_VISIBLE void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					  enum pending_timeout reason, int secs)
{
	time_t now;

	time(&now);

	wsi->pending_timeout_limit = now + secs;
	wsi->pending_timeout = reason;
}


/**
 * libwebsocket_get_socket_fd() - returns the socket file descriptor
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 */

LWS_VISIBLE int
libwebsocket_get_socket_fd(struct libwebsocket *wsi)
{
	return wsi->sock;
}

#ifdef LWS_LATENCY
void
lws_latency(struct libwebsocket_context *context, struct libwebsocket *wsi,
				     const char *action, int ret, int completed)
{
	unsigned long long u;
	char buf[256];

	u = time_in_microseconds();

	if (!action) {
		wsi->latency_start = u;
		if (!wsi->action_start)
			wsi->action_start = u;
		return;
	}
	if (completed) {
		if (wsi->action_start == wsi->latency_start)
			sprintf(buf,
			  "Completion first try lat %lluus: %p: ret %d: %s\n",
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		else
			sprintf(buf,
			  "Completion %lluus: lat %lluus: %p: ret %d: %s\n",
				u - wsi->action_start,
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		wsi->action_start = 0;
	} else
		sprintf(buf, "lat %lluus: %p: ret %d: %s\n",
			      u - wsi->latency_start, (void *)wsi, ret, action);

	if (u - wsi->latency_start > context->worst_latency) {
		context->worst_latency = u - wsi->latency_start;
		strcpy(context->worst_latency_info, buf);
	}
	lwsl_latency("%s", buf);
}
#endif



/**
 * libwebsocket_rx_flow_control() - Enable and disable socket servicing for
 *				receieved packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * @wsi:	Websocket connection instance to get callback for
 * @enable:	0 = disable read servicing for this connection, 1 = enable
 */

LWS_VISIBLE int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable)
{
	if (enable == (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW))
		return 0;

	lwsl_info("libwebsocket_rx_flow_control(0x%p, %d)\n", wsi, enable);
	wsi->u.ws.rxflow_change_to = LWS_RXFLOW_PENDING_CHANGE | !!enable;

	return 0;
}

/**
 * libwebsocket_rx_flow_allow_all_protocol() - Allow all connections with this protocol to receive
 *
 * When the user server code realizes it can accept more input, it can
 * call this to have the RX flow restriction removed from all connections using
 * the given protocol.
 *
 * @protocol:	all connections using this protocol will be allowed to receive
 */

LWS_VISIBLE void
libwebsocket_rx_flow_allow_all_protocol(
				const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			libwebsocket_rx_flow_control(wsi, LWS_RXFLOW_ALLOW);
	}
}


/**
 * libwebsocket_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * @context:	Websocket context
 */
LWS_VISIBLE extern const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *context)
{
	return (const char *)context->canonical_hostname;
}

int user_callback_handle_rxflow(callback_function callback_function,
		struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len)
{
	int n;

	n = callback_function(context, wsi, reason, user, in, len);
	if (!n)
		n = _libwebsocket_rx_flow_control(wsi);

	return n;
}


/**
 * libwebsocket_set_proxy() - Setups proxy to libwebsocket_context.
 * @context:	pointer to struct libwebsocket_context you want set proxy to
 * @proxy: pointer to c string containing proxy in format address:port
 *
 * Returns 0 if proxy string was parsed and proxy was setup. 
 * Returns -1 if @proxy is NULL or has incorrect format.
 *
 * This is only required if your OS does not provide the http_proxy
 * enviroment variable (eg, OSX)
 *
 *   IMPORTANT! You should call this function right after creation of the
 *   libwebsocket_context and before call to connect. If you call this
 *   function after connect behavior is undefined.
 *   This function will override proxy settings made on libwebsocket_context
 *   creation with genenv() call.
 */

LWS_VISIBLE int
libwebsocket_set_proxy(struct libwebsocket_context *context, const char *proxy)
{
	char *p;
	
	if (!proxy)
		return -1;

	strncpy(context->http_proxy_address, proxy,
				sizeof(context->http_proxy_address) - 1);
	context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';
	
	p = strchr(context->http_proxy_address, ':');
	if (!p) {
		lwsl_err("http_proxy needs to be ads:port\n");

		return -1;
	}
	*p = '\0';
	context->http_proxy_port = atoi(p + 1);
	
	lwsl_notice(" Proxy %s:%u\n", context->http_proxy_address,
						context->http_proxy_port);

	return 0;
}

/**
 * libwebsockets_get_protocol() - Returns a protocol pointer from a websocket
 *				  connection.
 * @wsi:	pointer to struct websocket you want to know the protocol of
 *
 *
 *	Some apis can act on all live connections of a given protocol,
 *	this is how you can get a pointer to the active protocol if needed.
 */

LWS_VISIBLE const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi)
{
	return wsi->protocol;
}

LWS_VISIBLE int
libwebsocket_is_final_fragment(struct libwebsocket *wsi)
{
	return wsi->u.ws.final;
}

LWS_VISIBLE unsigned char
libwebsocket_get_reserved_bits(struct libwebsocket *wsi)
{
	return wsi->u.ws.rsv;
}

int
libwebsocket_ensure_user_space(struct libwebsocket *wsi)
{
	if (!wsi->protocol)
		return 1;

	/* allocate the per-connection user memory (if any) */

	if (wsi->protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = malloc(
				  wsi->protocol->per_session_data_size);
		if (wsi->user_space  == NULL) {
			lwsl_err("Out of memory for conn user space\n");
			return 1;
		}
		memset(wsi->user_space, 0,
					 wsi->protocol->per_session_data_size);
	}
	return 0;
}

LWS_VISIBLE void lwsl_emit_stderr(int level, const char *line)
{
	char buf[300];
	unsigned long long now;
	int n;

	buf[0] = '\0';
	for (n = 0; n < LLL_COUNT; n++)
		if (level == (1 << n)) {
			now = time_in_microseconds() / 100;
			sprintf(buf, "[%lu:%04d] %s: ", (unsigned long) now / 10000,
				(int)(now % 10000), log_level_names[n]);
			break;
		}

	fprintf(stderr, "%s%s", buf, line);
}


LWS_VISIBLE void _lws_log(int filter, const char *format, ...)
{
	char buf[256];
	va_list ap;

	if (!(log_level & filter))
		return;

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	buf[sizeof(buf) - 1] = '\0';
	va_end(ap);

	lwsl_emit(filter, buf);
}

/**
 * lws_set_log_level() - Set the logging bitfield
 * @level:	OR together the LLL_ debug contexts you want output from
 * @log_emit_function:	NULL to leave it as it is, or a user-supplied
 *			function to perform log string emission instead of
 *			the default stderr one.
 *
 *	log level defaults to "err", "warn" and "notice" contexts enabled and
 *	emission on stderr.
 */

LWS_VISIBLE void lws_set_log_level(int level, void (*log_emit_function)(int level,
							      const char *line))
{
	log_level = level;
	if (log_emit_function)
		lwsl_emit = log_emit_function;
}

/***************************************************
 * external/libwebsockets/src/lws-plat-win.cpp
 ***************************************************/

#if defined(WIN32) || defined(_WIN32)

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

unsigned long long
time_in_microseconds()
{
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
	FILETIME filetime;
	ULARGE_INTEGER datetime;

#ifdef _WIN32_WCE
	GetCurrentFT(&filetime);
#else
	GetSystemTimeAsFileTime(&filetime);
#endif

	/*
	 * As per Windows documentation for FILETIME, copy the resulting FILETIME structure to a
	 * ULARGE_INTEGER structure using memcpy (using memcpy instead of direct assignment can
	 * prevent alignment faults on 64-bit Windows).
	 */
	memcpy(&datetime, &filetime, sizeof(datetime));

	/* Windows file times are in 100s of nanoseconds. */
	return (datetime.QuadPart - DELTA_EPOCH_IN_MICROSECS) / 10;
}

#ifdef _WIN32_WCE
time_t time(time_t *t)
{
	time_t ret = time_in_microseconds() / 1000000;
	*t = ret;
	return ret;
}
#endif

LWS_VISIBLE int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	int n;
	char *p = (char *)buf;

	for (n = 0; n < len; n++)
		p[n] = (unsigned char)rand();

	return n;
}

LWS_VISIBLE int lws_send_pipe_choked(struct libwebsocket *wsi)
{
	return wsi->sock_send_blocking;
}

LWS_VISIBLE int lws_poll_listen_fd(struct libwebsocket_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	assert(fd->events == LWS_POLLIN);

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(fd->fd + 1, &readfds, NULL, NULL, &tv);
}

/**
 * libwebsocket_cancel_service() - Cancel servicing of pending websocket activity
 * @context:	Websocket context
 *
 *	This function let a call to libwebsocket_service() waiting for a timeout
 *	immediately return.
 */
LWS_VISIBLE void
libwebsocket_cancel_service(struct libwebsocket_context *context)
{
	WSASetEvent(context->events[0]);
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	lwsl_emit_stderr(level, line);
}

LWS_VISIBLE int
lws_plat_service(struct libwebsocket_context *context, int timeout_ms)
{
	int n;
	int i;
	DWORD ev;
	WSANETWORKEVENTS networkevents;
	struct libwebsocket_pollfd *pfd;

	/* stay dead once we are dead */

	if (context == NULL)
		return 1;

	context->service_tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);

	for (i = 0; i < context->fds_count; ++i) {
		pfd = &context->fds[i];
		if (pfd->fd == context->listen_service_fd)
			continue;

		if (pfd->events & LWS_POLLOUT) {
			if (context->lws_lookup[pfd->fd]->sock_send_blocking)
				continue;
			pfd->revents = LWS_POLLOUT;
			n = libwebsocket_service_fd(context, pfd);
			if (n < 0)
				return n;
		}
	}

	ev = WSAWaitForMultipleEvents(context->fds_count + 1,
				     context->events, FALSE, timeout_ms, FALSE);
	context->service_tid = 0;

	if (ev == WSA_WAIT_TIMEOUT) {
		libwebsocket_service_fd(context, NULL);
		return 0;
	}

	if (ev == WSA_WAIT_EVENT_0) {
		WSAResetEvent(context->events[0]);
		return 0;
	}

	if (ev < WSA_WAIT_EVENT_0 || ev > WSA_WAIT_EVENT_0 + context->fds_count)
		return -1;

	pfd = &context->fds[ev - WSA_WAIT_EVENT_0 - 1];

	if (WSAEnumNetworkEvents(pfd->fd,
			context->events[ev - WSA_WAIT_EVENT_0],
					      &networkevents) == SOCKET_ERROR) {
		lwsl_err("WSAEnumNetworkEvents() failed with error %d\n",
								     LWS_ERRNO);
		return -1;
	}

	pfd->revents = networkevents.lNetworkEvents;

	if (pfd->revents & LWS_POLLOUT)
		context->lws_lookup[pfd->fd]->sock_send_blocking = FALSE;

	return libwebsocket_service_fd(context, pfd);
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct libwebsocket_context *context, int fd)
{
	int optval = 1;
	int optlen = sizeof(optval);
	u_long optl = 1;
	DWORD dwBytesRet;
	struct tcp_keepalive alive;
	struct protoent *tcp_proto;
			
	if (context->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
					     (const char *)&optval, optlen) < 0)
			return 1;

		alive.onoff = TRUE;
		alive.keepalivetime = context->ka_time;
		alive.keepaliveinterval = context->ka_interval;

		if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), 
					      NULL, 0, &dwBytesRet, NULL, NULL))
			return 1;
	}

	/* Disable Nagle */
	optval = 1;
	tcp_proto = getprotobyname("TCP");
	setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, (const char *)&optval, optlen);

	/* We are nonblocking... */
	ioctlsocket(fd, FIONBIO, &optl);

	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
}

LWS_VISIBLE int
lws_plat_init_fd_tables(struct libwebsocket_context *context)
{
	context->events = (WSAEVENT *)malloc(sizeof(WSAEVENT) *
							(context->max_fds + 1));
	if (context->events == NULL) {
		lwsl_err("Unable to allocate events array for %d connections\n",
			context->max_fds);
		return 1;
	}
	
	context->fds_count = 0;
	context->events[0] = WSACreateEvent();
	
	context->fd_random = 0;

	return 0;
}

LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro from Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (!err)
		return 0;
	/*
	 * Tell the user that we could not find a usable
	 * Winsock DLL
	 */
	lwsl_err("WSAStartup failed with error: %d\n", err);

	return 1;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct libwebsocket_context *context)
{
	if (context->events) {
		WSACloseEvent(context->events[0]);
		free(context->events);
	}
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct libwebsocket_context *context)
{
	WSACleanup();
}

LWS_VISIBLE int
interface_to_sa(struct libwebsocket_context *context,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	return -1;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct libwebsocket_context *context,
						       struct libwebsocket *wsi)
{
	context->fds[context->fds_count++].revents = 0;
	context->events[context->fds_count] = WSACreateEvent();
	WSAEventSelect(wsi->sock, context->events[context->fds_count], LWS_POLLIN);
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct libwebsocket_context *context,
						struct libwebsocket *wsi, int m)
{
	WSACloseEvent(context->events[m + 1]);
	context->events[m + 1] = context->events[context->fds_count + 1];
}

LWS_VISIBLE void
lws_plat_service_periodic(struct libwebsocket_context *context)
{
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct libwebsocket_context *context,
		      struct libwebsocket *wsi, struct libwebsocket_pollfd *pfd)
{
	long networkevents = LWS_POLLOUT | LWS_POLLHUP;
		
	if ((pfd->events & LWS_POLLIN))
		networkevents |= LWS_POLLIN;

	if (WSAEventSelect(wsi->sock,
			context->events[wsi->position_in_fds_table + 1],
					       networkevents) != SOCKET_ERROR)
		return 0;

	lwsl_err("WSAEventSelect() failed with error %d\n", LWS_ERRNO);

	return 1;
}

LWS_VISIBLE HANDLE
lws_plat_open_file(const char* filename, unsigned long* filelen)
{
	HANDLE ret;
	WCHAR buffer[MAX_PATH];

	MultiByteToWideChar(CP_UTF8, 0, filename, -1, buffer,
				sizeof(buffer) / sizeof(buffer[0]));
	ret = CreateFileW(buffer, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ret != LWS_INVALID_FILE)
		*filelen = GetFileSize(ret, NULL);

	return ret;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{ 
	WCHAR *buffer;
	DWORD bufferlen = cnt;
	BOOL ok = FALSE;

	buffer = (WCHAR*)malloc(bufferlen);
	if (!buffer) {
		lwsl_err("Out of memory\n");
		return NULL;
	}

	if (af == AF_INET) {
		struct sockaddr_in srcaddr;
		bzero(&srcaddr, sizeof(srcaddr));
		srcaddr.sin_family = AF_INET;
		memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr, sizeof(srcaddr), 0, buffer, &bufferlen))
			ok = TRUE;
#ifdef LWS_USE_IPV6
	} else if (af == AF_INET6) {
		struct sockaddr_in6 srcaddr;
		bzero(&srcaddr, sizeof(srcaddr));
		srcaddr.sin6_family = AF_INET6;
		memcpy(&(srcaddr.sin6_addr), src, sizeof(srcaddr.sin6_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr, sizeof(srcaddr), 0, buffer, &bufferlen))
			ok = TRUE;
#endif
	} else
		lwsl_err("Unsupported type\n");

	if (!ok) {
		int rv = WSAGetLastError();
		lwsl_err("WSAAddressToString() : %d\n", rv);
	} else {
		if (WideCharToMultiByte(CP_ACP, 0, buffer, bufferlen, dst, cnt, 0, NULL) <= 0)
			ok = FALSE;
	}

	free(buffer);
	return ok ? dst : NULL;
}

#endif

/***************************************************
 * external/libwebsockets/src/lws-plat-unix.cpp
 ***************************************************/

#if !(defined(WIN32) || defined(_WIN32))

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

/*
 * included from libwebsockets.c for unix builds
 */

unsigned long long time_in_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

LWS_VISIBLE int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	return read(context->fd_random, (char *)buf, len);
}

LWS_VISIBLE int lws_send_pipe_choked(struct libwebsocket *wsi)
{
	struct libwebsocket_pollfd fds;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (wsi->truncated_send_len)
		return 1;

	fds.fd = wsi->sock;
	fds.events = POLLOUT;
	fds.revents = 0;

	if (poll(&fds, 1, 0) != 1)
		return 1;

	if ((fds.revents & POLLOUT) == 0)
		return 1;

	/* okay to send another packet without blocking */

	return 0;
}

LWS_VISIBLE int
lws_poll_listen_fd(struct libwebsocket_pollfd *fd)
{
	return poll(fd, 1, 0);
}

/*
 * This is just used to interrupt poll waiting
 * we don't have to do anything with it.
 */
static void lws_sigusr2(int sig)
{
}

/**
 * libwebsocket_cancel_service() - Cancel servicing of pending websocket activity
 * @context:	Websocket context
 *
 *	This function let a call to libwebsocket_service() waiting for a timeout
 *	immediately return.
 */
LWS_VISIBLE void
libwebsocket_cancel_service(struct libwebsocket_context *context)
{
	char buf = 0;

	if (write(context->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
		lwsl_err("Cannot write to dummy pipe");
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	int syslog_level = LOG_DEBUG;

	switch (level) {
	case LLL_ERR:
		syslog_level = LOG_ERR;
		break;
	case LLL_WARN:
		syslog_level = LOG_WARNING;
		break;
	case LLL_NOTICE:
		syslog_level = LOG_NOTICE;
		break;
	case LLL_INFO:
		syslog_level = LOG_INFO;
		break;
	}
	syslog(syslog_level, "%s", line);
}

LWS_VISIBLE int
lws_plat_service(struct libwebsocket_context *context, int timeout_ms)
{
	int n;
	int m;
	char buf;

	/* stay dead once we are dead */

	if (!context)
		return 1;

	lws_libev_run(context);

	context->service_tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);

	n = poll(context->fds, context->fds_count, timeout_ms);
	context->service_tid = 0;

	if (n == 0) /* poll timeout */ {
		libwebsocket_service_fd(context, NULL);
		return 0;
	}

	if (n < 0) {
		if (LWS_ERRNO != LWS_EINTR)
			return -1;
		return 0;
	}

	/* any socket with events to service? */

	for (n = 0; n < context->fds_count; n++) {
		if (!context->fds[n].revents)
			continue;

		if (context->fds[n].fd == context->dummy_pipe_fds[0]) {
			if (read(context->fds[n].fd, &buf, 1) != 1)
				lwsl_err("Cannot read from dummy pipe.");
			continue;
		}

		m = libwebsocket_service_fd(context, &context->fds[n]);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	return 0;
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct libwebsocket_context *context, int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__)
	struct protoent *tcp_proto;
#endif

	if (context->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
					     (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
        defined(__CYGWIN__) || defined(__OpenBSD__)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#else
		/* set the keepalive conditions we want on it too */
		optval = context->ka_time;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPIDLE,
					     (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_interval;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPINTVL,
					     (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_probes;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPCNT,
					     (const void *)&optval, optlen) < 0)
			return 1;
#endif
	}

	/* Disable Nagle */
	optval = 1;
#if !defined(__APPLE__) && !defined(__FreeBSD__) && !defined(__NetBSD__) && \
    !defined(__OpenBSD__)
	setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen);
#else
	tcp_proto = getprotobyname("TCP");
	setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, &optval, optlen);
#endif

	/* We are nonblocking... */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
	if (info->gid != -1)
		if (setgid(info->gid))
			lwsl_warn("setgid: %s\n", strerror(LWS_ERRNO));
	if (info->uid != -1)
		if (setuid(info->uid))
			lwsl_warn("setuid: %s\n", strerror(LWS_ERRNO));	
}

LWS_VISIBLE int
lws_plat_init_fd_tables(struct libwebsocket_context *context)
{
	if (lws_libev_init_fd_table(context))
		/* libev handled it instead */
		return 0;

	if (pipe(context->dummy_pipe_fds)) {
		lwsl_err("Unable to create pipe\n");
		return 1;
	}

	/* use the read end of pipe as first item */
	context->fds[0].fd = context->dummy_pipe_fds[0];
	context->fds[0].events = LWS_POLLIN;
	context->fds[0].revents = 0;
	context->fds_count = 1;
	
	context->fd_random = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
	if (context->fd_random < 0) {
		lwsl_err("Unable to open random device %s %d\n",
				    SYSTEM_RANDOM_FILEPATH, context->fd_random);
		return 1;
	}

	return 0;
}

static void sigpipe_handler(int x)
{
}


LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	sigset_t mask;

	signal(SIGUSR2, lws_sigusr2);
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);

	sigprocmask(SIG_BLOCK, &mask, NULL);
	
	signal(SIGPIPE, sigpipe_handler);

	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct libwebsocket_context *context)
{
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct libwebsocket_context *context)
{
	close(context->dummy_pipe_fds[0]);
	close(context->dummy_pipe_fds[1]);
	close(context->fd_random);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

LWS_VISIBLE int
interface_to_sa(struct libwebsocket_context *context,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;

	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
#endif

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL && rc; ifc = ifc->ifa_next) {
		if (!ifc->ifa_addr)
			continue;

		lwsl_info(" interface %s vs %s\n", ifc->ifa_name, ifname);

		if (strcmp(ifc->ifa_name, ifname))
			continue;

		switch (ifc->ifa_addr->sa_family) {
		case AF_INET:
#ifdef LWS_USE_IPV6
			if (LWS_IPV6_ENABLED(context)) {
				/* map IPv4 to IPv6 */
				bzero((char *)&addr6->sin6_addr,
						sizeof(struct in6_addr));
				addr6->sin6_addr.s6_addr[10] = 0xff;
				addr6->sin6_addr.s6_addr[11] = 0xff;
				memcpy(&addr6->sin6_addr.s6_addr[12],
					&((struct sockaddr_in *)ifc->ifa_addr)->sin_addr,
							sizeof(struct in_addr));
			} else
#endif
				memcpy(addr,
					(struct sockaddr_in *)ifc->ifa_addr,
						    sizeof(struct sockaddr_in));
			break;
#ifdef LWS_USE_IPV6
		case AF_INET6:
			if (rc >= 0)
				break;
			memcpy(&addr6->sin6_addr,
			  &((struct sockaddr_in6 *)ifc->ifa_addr)->sin6_addr,
						       sizeof(struct in6_addr));
			break;
#endif
		default:
			continue;
		}
		rc = 0;
	}

	freeifaddrs(ifr);
	
	if (rc == -1) {
		/* check if bind to IP adddress */
#ifdef LWS_USE_IPV6
		if (inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1)
			rc = 0;
		else
#endif
		if (inet_pton(AF_INET, ifname, &addr->sin_addr) == 1)
			rc = 0;
	}

	return rc;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct libwebsocket_context *context,
						       struct libwebsocket *wsi)
{
	lws_libev_io(context, wsi, LWS_EV_START | LWS_EV_READ);
	context->fds[context->fds_count++].revents = 0;
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct libwebsocket_context *context,
						struct libwebsocket *wsi, int m)
{
}

LWS_VISIBLE void
lws_plat_service_periodic(struct libwebsocket_context *context)
{
	/* if our parent went down, don't linger around */
	if (context->started_with_parent &&
			      kill(context->started_with_parent, 0) < 0)
		kill(getpid(), SIGTERM);
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct libwebsocket_context *context,
		      struct libwebsocket *wsi, struct libwebsocket_pollfd *pfd)
{
	return 0;
}

LWS_VISIBLE int
lws_plat_open_file(const char* filename, unsigned long* filelen)
{
	struct stat stat_buf;
	int ret = open(filename, O_RDONLY);

	if (ret < 0)
		return LWS_INVALID_FILE;

	fstat(ret, &stat_buf);
	*filelen = stat_buf.st_size;
	return ret;
}

#ifdef LWS_USE_IPV6
LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{ 
	return inet_ntop(af, src, dst, cnt);
}
#endif

#endif
/***************************************************
 * external/libwebsockets/src/output.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

static int
libwebsocket_0405_frame_mask_generate(struct libwebsocket *wsi)
{
	int n;

	/* fetch the per-frame nonce */

	n = libwebsockets_get_random(wsi->protocol->owning_server,
					   wsi->u.ws.frame_masking_nonce_04, 4);
	if (n != 4) {
		lwsl_parser("Unable to read from random device %s %d\n",
						     SYSTEM_RANDOM_FILEPATH, n);
		return 1;
	}

	/* start masking from first byte of masking key buffer */
	wsi->u.ws.frame_mask_index = 0;

	return 0;
}

#ifdef _DEBUG

LWS_VISIBLE void lwsl_hexdump(void *vbuf, size_t len)
{
	int n;
	int m;
	int start;
	unsigned char *buf = (unsigned char *)vbuf;
	char line[80];
	char *p;

	lwsl_parser("\n");

	for (n = 0; n < len;) {
		start = n;
		p = line;

		p += sprintf(p, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			p += sprintf(p, "%02X ", buf[n++]);
		while (m++ < 16)
			p += sprintf(p, "   ");

		p += sprintf(p, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] < 127)
				*p++ = buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		lwsl_debug("%s", line);
	}
	lwsl_debug("\n");
}

#endif

/*
 * notice this returns number of bytes consumed, or -1
 */

int lws_issue_raw(struct libwebsocket *wsi, unsigned char *buf, size_t len)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;
	int n;
	size_t real_len = len;
	int m;
	
	if (!len)
		return 0;
	/* just ignore sends after we cleared the truncation buffer */
	if (wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE &&
						!wsi->truncated_send_len)
		return len;

	if (wsi->truncated_send_len && (buf < wsi->truncated_send_malloc ||
			buf > (wsi->truncated_send_malloc +
				wsi->truncated_send_len +
				wsi->truncated_send_offset))) {
		lwsl_err("****** %x Sending new, pending truncated ...\n", wsi);
		assert(0);
	}

	m = lws_ext_callback_for_each_active(wsi,
			LWS_EXT_CALLBACK_PACKET_TX_DO_SEND, &buf, len);
	if (m < 0)
		return -1;
	if (m) /* handled */ {
		n = m;
		goto handle_truncated_send;
	}
	if (wsi->sock < 0)
		lwsl_warn("** error invalid sock but expected to send\n");

	/*
	 * nope, send it on the socket directly
	 */
	lws_latency_pre(context, wsi);
	n = lws_ssl_capable_write(wsi, buf, len);
	lws_latency(context, wsi, "send lws_issue_raw", n, n == len);

	switch (n) {
	case LWS_SSL_CAPABLE_ERROR:
		return -1;
	case LWS_SSL_CAPABLE_MORE_SERVICE:
		/* nothing got sent, not fatal, retry the whole thing later */
		n = 0;
		break;
	}

handle_truncated_send:
	/*
	 * we were already handling a truncated send?
	 */
	if (wsi->truncated_send_len) {
		lwsl_info("***** %x partial send moved on by %d (vs %d)\n",
							     wsi, n, real_len);
		wsi->truncated_send_offset += n;
		wsi->truncated_send_len -= n;

		if (!wsi->truncated_send_len) {
			lwsl_info("***** %x partial send completed\n", wsi);
			/* done with it, but don't free it */
			n = real_len;
			if (wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
				lwsl_info("***** %x signalling to close now\n", wsi);
				return -1; /* retry closing now */
			}
		}
		/* always callback on writeable */
		libwebsocket_callback_on_writable(
					     wsi->protocol->owning_server, wsi);

		return n;
	}

	if (n == real_len)
		/* what we just sent went out cleanly */
		return n;

	if (n && wsi->u.ws.clean_buffer)
		/*
		 * This buffer unaffected by extension rewriting.
		 * It means the user code is expected to deal with
		 * partial sends.  (lws knows the header was already
		 * sent, so on next send will just resume sending
		 * payload)
		 */
		 return n;

	/*
	 * Newly truncated send.  Buffer the remainder (it will get
	 * first priority next time the socket is writable)
	 */
	lwsl_info("***** %x new partial sent %d from %d total\n",
						      wsi, n, real_len);

	/*
	 *  - if we still have a suitable malloc lying around, use it
	 *  - or, if too small, reallocate it
	 *  - or, if no buffer, create it
	 */
	if (!wsi->truncated_send_malloc ||
			real_len - n > wsi->truncated_send_allocation) {
		if (wsi->truncated_send_malloc)
			free(wsi->truncated_send_malloc);

		wsi->truncated_send_allocation = real_len - n;
		wsi->truncated_send_malloc = (unsigned char*)malloc(real_len - n);
		if (!wsi->truncated_send_malloc) {
			lwsl_err("truncated send: unable to malloc %d\n",
							  real_len - n);
			return -1;
		}
	}
	wsi->truncated_send_offset = 0;
	wsi->truncated_send_len = real_len - n;
	memcpy(wsi->truncated_send_malloc, buf + n, real_len - n);

	/* since something buffered, force it to get another chance to send */
	libwebsocket_callback_on_writable(wsi->protocol->owning_server, wsi);

	return real_len;
}

/**
 * libwebsocket_write() - Apply protocol then write data to client
 * @wsi:	Websocket instance (available from user callback)
 * @buf:	The data to send.  For data being sent on a websocket
 *		connection (ie, not default http), this buffer MUST have
 *		LWS_SEND_BUFFER_PRE_PADDING bytes valid BEFORE the pointer
 *		and an additional LWS_SEND_BUFFER_POST_PADDING bytes valid
 *		in the buffer after (buf + len).  This is so the protocol
 *		header and trailer data can be added in-situ.
 * @len:	Count of the data bytes in the payload starting from buf
 * @protocol:	Use LWS_WRITE_HTTP to reply to an http connection, and one
 *		of LWS_WRITE_BINARY or LWS_WRITE_TEXT to send appropriate
 *		data on a websockets connection.  Remember to allow the extra
 *		bytes before and after buf if LWS_WRITE_BINARY or LWS_WRITE_TEXT
 *		are used.
 *
 *	This function provides the way to issue data back to the client
 *	for both http and websocket protocols.
 *
 *	In the case of sending using websocket protocol, be sure to allocate
 *	valid storage before and after buf as explained above.  This scheme
 *	allows maximum efficiency of sending data and protocol in a single
 *	packet while not burdening the user code with any protocol knowledge.
 *
 *	Return may be -1 for a fatal error needing connection close, or a
 *	positive number reflecting the amount of bytes actually sent.  This
 *	can be less than the requested number of bytes due to OS memory
 *	pressure at any given time.
 */

LWS_VISIBLE int libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf,
			  size_t len, enum libwebsocket_write_protocol protocol)
{
	int n;
	int pre = 0;
	int post = 0;
	int masked7 = wsi->mode == LWS_CONNMODE_WS_CLIENT;
	unsigned char *dropmask = NULL;
	unsigned char is_masked_bit = 0;
	size_t orig_len = len;
	struct lws_tokens eff_buf;

	if (len == 0 && protocol != LWS_WRITE_CLOSE &&
		     protocol != LWS_WRITE_PING && protocol != LWS_WRITE_PONG) {
		lwsl_warn("zero length libwebsocket_write attempt\n");
		return 0;
	}

	if (protocol == LWS_WRITE_HTTP)
		goto send_raw;

	/* websocket protocol, either binary or text */

	if (wsi->state != WSI_STATE_ESTABLISHED)
		return -1;

	/* if we are continuing a frame that already had its header done */

	if (wsi->u.ws.inside_frame)
		goto do_more_inside_frame;

	/* if he wants all partials buffered, never have a clean_buffer */
	wsi->u.ws.clean_buffer = !wsi->protocol->no_buffer_all_partial_tx;

	/*
	 * give a chance to the extensions to modify payload
	 * pre-TX mangling is not allowed to truncate
	 */
	eff_buf.token = (char *)buf;
	eff_buf.token_len = len;

	switch (protocol) {
	case LWS_WRITE_PING:
	case LWS_WRITE_PONG:
	case LWS_WRITE_CLOSE:
		break;
	default:
		if (lws_ext_callback_for_each_active(wsi,
			       LWS_EXT_CALLBACK_PAYLOAD_TX, &eff_buf, 0) < 0)
			return -1;
	}

	/*
	 * an extension did something we need to keep... for example, if
	 * compression extension, it has already updated its state according
	 * to this being issued
	 */
	if ((char *)buf != eff_buf.token)
		/*
		 * extension recreated it:
		 * need to buffer this if not all sent
		 */
		wsi->u.ws.clean_buffer = 0;

	buf = (unsigned char *)eff_buf.token;
	len = eff_buf.token_len;

	switch (wsi->ietf_spec_revision) {
	case 13:

		if (masked7) {
			pre += 4;
			dropmask = &buf[0 - pre];
			is_masked_bit = 0x80;
		}

		switch (protocol & 0xf) {
		case LWS_WRITE_TEXT:
			n = LWS_WS_OPCODE_07__TEXT_FRAME;
			break;
		case LWS_WRITE_BINARY:
			n = LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		case LWS_WRITE_CONTINUATION:
			n = LWS_WS_OPCODE_07__CONTINUATION;
			break;

		case LWS_WRITE_CLOSE:
			n = LWS_WS_OPCODE_07__CLOSE;

			/*
			 * 06+ has a 2-byte status code in network order
			 * we can do this because we demand post-buf
			 */

			if (wsi->u.ws.close_reason) {
				/* reason codes count as data bytes */
				buf -= 2;
				buf[0] = wsi->u.ws.close_reason >> 8;
				buf[1] = wsi->u.ws.close_reason;
				len += 2;
			}
			break;
		case LWS_WRITE_PING:
			n = LWS_WS_OPCODE_07__PING;
			break;
		case LWS_WRITE_PONG:
			n = LWS_WS_OPCODE_07__PONG;
			break;
		default:
			lwsl_warn("lws_write: unknown write opc / protocol\n");
			return -1;
		}

		if (!(protocol & LWS_WRITE_NO_FIN))
			n |= 1 << 7;

		if (len < 126) {
			pre += 2;
			buf[-pre] = n;
			buf[-pre + 1] = len | is_masked_bit;
		} else {
			if (len < 65536) {
				pre += 4;
				buf[-pre] = n;
				buf[-pre + 1] = 126 | is_masked_bit;
				buf[-pre + 2] = len >> 8;
				buf[-pre + 3] = len;
			} else {
				pre += 10;
				buf[-pre] = n;
				buf[-pre + 1] = 127 | is_masked_bit;
#if defined __LP64__
					buf[-pre + 2] = (len >> 56) & 0x7f;
					buf[-pre + 3] = len >> 48;
					buf[-pre + 4] = len >> 40;
					buf[-pre + 5] = len >> 32;
#else
					buf[-pre + 2] = 0;
					buf[-pre + 3] = 0;
					buf[-pre + 4] = 0;
					buf[-pre + 5] = 0;
#endif
				buf[-pre + 6] = len >> 24;
				buf[-pre + 7] = len >> 16;
				buf[-pre + 8] = len >> 8;
				buf[-pre + 9] = len;
			}
		}
		break;
	}

do_more_inside_frame:

	/*
	 * Deal with masking if we are in client -> server direction and
	 * the protocol demands it
	 */

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT) {

		if (!wsi->u.ws.inside_frame)
			if (libwebsocket_0405_frame_mask_generate(wsi)) {
				lwsl_err("frame mask generation failed\n");
				return -1;
			}

		/*
		 * in v7, just mask the payload
		 */
		if (dropmask) { /* never set if already inside frame */
			for (n = 4; n < (int)len + 4; n++)
				dropmask[n] = dropmask[n] ^
				wsi->u.ws.frame_masking_nonce_04[
					(wsi->u.ws.frame_mask_index++) & 3];

			/* copy the frame nonce into place */
			memcpy(dropmask, wsi->u.ws.frame_masking_nonce_04, 4);
		}
	}

send_raw:
	switch (protocol) {
	case LWS_WRITE_CLOSE:
/*		lwsl_hexdump(&buf[-pre], len + post); */
	case LWS_WRITE_HTTP:
	case LWS_WRITE_PONG:
	case LWS_WRITE_PING:
		return lws_issue_raw(wsi, (unsigned char *)buf - pre,
							      len + pre + post);
	default:
		break;
	}

	wsi->u.ws.inside_frame = 1;

	/*
	 * give any active extensions a chance to munge the buffer
	 * before send.  We pass in a pointer to an lws_tokens struct
	 * prepared with the default buffer and content length that's in
	 * there.  Rather than rewrite the default buffer, extensions
	 * that expect to grow the buffer can adapt .token to
	 * point to their own per-connection buffer in the extension
	 * user allocation.  By default with no extensions or no
	 * extension callback handling, just the normal input buffer is
	 * used then so it is efficient.
	 *
	 * callback returns 1 in case it wants to spill more buffers
	 *
	 * This takes care of holding the buffer if send is incomplete, ie,
	 * if wsi->u.ws.clean_buffer is 0 (meaning an extension meddled with
	 * the buffer).  If wsi->u.ws.clean_buffer is 1, it will instead
	 * return to the user code how much OF THE USER BUFFER was consumed.
	 */

	n = lws_issue_raw_ext_access(wsi, buf - pre, len + pre + post);
	if (n <= 0)
		return n;

	if (n == len + pre + post) {
		/* everything in the buffer was handled (or rebuffered...) */
		wsi->u.ws.inside_frame = 0;
		return orig_len;
	}

	/*
	 * it is how many bytes of user buffer got sent... may be < orig_len
	 * in which case callback when writable has already been arranged
	 * and user code can call libwebsocket_write() again with the rest
	 * later.
	 */

	return n - (pre + post);
}

LWS_VISIBLE int libwebsockets_serve_http_file_fragment(
		struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	int n;
	int m;

	while (!lws_send_pipe_choked(wsi)) {

		if (wsi->truncated_send_len) {
			if (lws_issue_raw(wsi, wsi->truncated_send_malloc +
					wsi->truncated_send_offset,
						       wsi->truncated_send_len) < 0) {
				lwsl_info("closing from libwebsockets_serve_http_file_fragment\n");
				return -1;
			}
			continue;
		}

		if (wsi->u.http.filepos == wsi->u.http.filelen)
			goto all_sent;

		compatible_file_read(n, wsi->u.http.fd, context->service_buffer,
					       sizeof(context->service_buffer));
		if (n < 0)
			return -1; /* caller will close */
		if (n) {
			m = libwebsocket_write(wsi, context->service_buffer, n,
								LWS_WRITE_HTTP);
			if (m < 0)
				return -1;

			wsi->u.http.filepos += m;
			if (m != n)
				/* adjust for what was not sent */
				compatible_file_seek_cur(wsi->u.http.fd, m - n);
		}
all_sent:
		if (!wsi->truncated_send_len &&
				wsi->u.http.filepos == wsi->u.http.filelen) {
			wsi->state = WSI_STATE_HTTP;

			if (wsi->protocol->callback)
				/* ignore callback returned value */
				user_callback_handle_rxflow(
					wsi->protocol->callback, context, wsi,
					LWS_CALLBACK_HTTP_FILE_COMPLETION,
					wsi->user_space, NULL, 0);
			return 1;  /* >0 indicates completed */
		}
	}

	lwsl_info("choked before able to send whole file (post)\n");
	libwebsocket_callback_on_writable(context, wsi);

	return 0; /* indicates further processing must be done */
}

LWS_VISIBLE int
lws_ssl_capable_read_no_ssl(struct libwebsocket *wsi, unsigned char *buf, int len)
{
	int n;

	n = recv(wsi->sock, (char*)buf, len, 0);
	if (n >= 0)
		return n;

	lwsl_warn("error on reading from skt\n");
	return LWS_SSL_CAPABLE_ERROR;
}

LWS_VISIBLE int
lws_ssl_capable_write_no_ssl(struct libwebsocket *wsi, unsigned char *buf, int len)
{
	int n;
	
	n = send(wsi->sock, (const char*)buf, len, 0);
	if (n >= 0)
		return n;

	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR) {
		if (LWS_ERRNO == LWS_EWOULDBLOCK)
			lws_set_blocking_send(wsi);

		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}
	lwsl_debug("ERROR writing len %d to skt %d\n", len, n);
	return LWS_SSL_CAPABLE_ERROR;
}

/***************************************************
 * external/libwebsockets/src/parsers.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

unsigned char lextable[] = {
	/* pos 0000:   0 */    0x67 /* 'g' */, 0x25, 0x00  /* (to 0x0025 state   1) */,
	0x70 /* 'p' */, 0x27, 0x00  /* (to 0x002A state   5) */,
	0x6F /* 'o' */, 0x30, 0x00  /* (to 0x0036 state  10) */,
	0x68 /* 'h' */, 0x3C, 0x00  /* (to 0x0045 state  18) */,
	0x63 /* 'c' */, 0x45, 0x00  /* (to 0x0051 state  23) */,
	0x73 /* 's' */, 0x60, 0x00  /* (to 0x006F state  34) */,
	0x75 /* 'u' */, 0x9F, 0x00  /* (to 0x00B1 state  64) */,
	0x0D /* '.' */, 0xB3, 0x00  /* (to 0x00C8 state  84) */,
	0x61 /* 'a' */, 0xEA, 0x00  /* (to 0x0102 state 134) */,
	0x69 /* 'i' */, 0x1D, 0x01  /* (to 0x0138 state 168) */,
	0x64 /* 'd' */, 0x9C, 0x01  /* (to 0x01BA state 270) */,
	0x72 /* 'r' */, 0x9F, 0x01  /* (to 0x01C0 state 275) */,
	0x08, /* fail */
	/* pos 0025:   1 */    0xE5 /* 'e' -> */,
	/* pos 0026:   2 */    0xF4 /* 't' -> */,
	/* pos 0027:   3 */    0xA0 /* ' ' -> */,
	/* pos 0028:   4 */    0x00, 0x00                  /* - terminal marker  0 - */,
	/* pos 002a:   5 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0031 state   6) */,
	0x72 /* 'r' */, 0x4B, 0x01  /* (to 0x0178 state 216) */,
	0x08, /* fail */
	/* pos 0031:   6 */    0xF3 /* 's' -> */,
	/* pos 0032:   7 */    0xF4 /* 't' -> */,
	/* pos 0033:   8 */    0xA0 /* ' ' -> */,
	/* pos 0034:   9 */    0x00, 0x01                  /* - terminal marker  1 - */,
	/* pos 0036:  10 */    0x70 /* 'p' */, 0x07, 0x00  /* (to 0x003D state  11) */,
	0x72 /* 'r' */, 0x81, 0x00  /* (to 0x00BA state  72) */,
	0x08, /* fail */
	/* pos 003d:  11 */    0xF4 /* 't' -> */,
	/* pos 003e:  12 */    0xE9 /* 'i' -> */,
	/* pos 003f:  13 */    0xEF /* 'o' -> */,
	/* pos 0040:  14 */    0xEE /* 'n' -> */,
	/* pos 0041:  15 */    0xF3 /* 's' -> */,
	/* pos 0042:  16 */    0xA0 /* ' ' -> */,
	/* pos 0043:  17 */    0x00, 0x02                  /* - terminal marker  2 - */,
	/* pos 0045:  18 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x004C state  19) */,
	0x74 /* 't' */, 0xB1, 0x00  /* (to 0x00F9 state 126) */,
	0x08, /* fail */
	/* pos 004c:  19 */    0xF3 /* 's' -> */,
	/* pos 004d:  20 */    0xF4 /* 't' -> */,
	/* pos 004e:  21 */    0xBA /* ':' -> */,
	/* pos 004f:  22 */    0x00, 0x03                  /* - terminal marker  3 - */,
	/* pos 0051:  23 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0058 state  24) */,
	0x61 /* 'a' */, 0x2B, 0x01  /* (to 0x017F state 222) */,
	0x08, /* fail */
	/* pos 0058:  24 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x005F state  25) */,
	0x6F /* 'o' */, 0x40, 0x01  /* (to 0x019B state 248) */,
	0x08, /* fail */
	/* pos 005f:  25 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x0066 state  26) */,
	0x74 /* 't' */, 0x3F, 0x01  /* (to 0x01A1 state 253) */,
	0x08, /* fail */
	/* pos 0066:  26 */    0xE5 /* 'e' -> */,
	/* pos 0067:  27 */    0xE3 /* 'c' -> */,
	/* pos 0068:  28 */    0xF4 /* 't' -> */,
	/* pos 0069:  29 */    0xE9 /* 'i' -> */,
	/* pos 006a:  30 */    0xEF /* 'o' -> */,
	/* pos 006b:  31 */    0xEE /* 'n' -> */,
	/* pos 006c:  32 */    0xBA /* ':' -> */,
	/* pos 006d:  33 */    0x00, 0x04                  /* - terminal marker  4 - */,
	/* pos 006f:  34 */    0xE5 /* 'e' -> */,
	/* pos 0070:  35 */    0xE3 /* 'c' -> */,
	/* pos 0071:  36 */    0xAD /* '-' -> */,
	/* pos 0072:  37 */    0xF7 /* 'w' -> */,
	/* pos 0073:  38 */    0xE5 /* 'e' -> */,
	/* pos 0074:  39 */    0xE2 /* 'b' -> */,
	/* pos 0075:  40 */    0xF3 /* 's' -> */,
	/* pos 0076:  41 */    0xEF /* 'o' -> */,
	/* pos 0077:  42 */    0xE3 /* 'c' -> */,
	/* pos 0078:  43 */    0xEB /* 'k' -> */,
	/* pos 0079:  44 */    0xE5 /* 'e' -> */,
	/* pos 007a:  45 */    0xF4 /* 't' -> */,
	/* pos 007b:  46 */    0xAD /* '-' -> */,
	/* pos 007c:  47 */    0x6B /* 'k' */, 0x19, 0x00  /* (to 0x0095 state  48) */,
	0x70 /* 'p' */, 0x28, 0x00  /* (to 0x00A7 state  55) */,
	0x64 /* 'd' */, 0x3F, 0x00  /* (to 0x00C1 state  78) */,
	0x76 /* 'v' */, 0x48, 0x00  /* (to 0x00CD state  87) */,
	0x6F /* 'o' */, 0x4E, 0x00  /* (to 0x00D6 state  95) */,
	0x65 /* 'e' */, 0x53, 0x00  /* (to 0x00DE state 102) */,
	0x61 /* 'a' */, 0x5C, 0x00  /* (to 0x00EA state 113) */,
	0x6E /* 'n' */, 0x61, 0x00  /* (to 0x00F2 state 120) */,
	0x08, /* fail */
	/* pos 0095:  48 */    0xE5 /* 'e' -> */,
	/* pos 0096:  49 */    0xF9 /* 'y' -> */,
	/* pos 0097:  50 */    0x31 /* '1' */, 0x0A, 0x00  /* (to 0x00A1 state  51) */,
	0x32 /* '2' */, 0x0A, 0x00  /* (to 0x00A4 state  53) */,
	0x3A /* ':' */, 0x2E, 0x00  /* (to 0x00CB state  86) */,
	0x08, /* fail */
	/* pos 00a1:  51 */    0xBA /* ':' -> */,
	/* pos 00a2:  52 */    0x00, 0x05                  /* - terminal marker  5 - */,
	/* pos 00a4:  53 */    0xBA /* ':' -> */,
	/* pos 00a5:  54 */    0x00, 0x06                  /* - terminal marker  6 - */,
	/* pos 00a7:  55 */    0xF2 /* 'r' -> */,
	/* pos 00a8:  56 */    0xEF /* 'o' -> */,
	/* pos 00a9:  57 */    0xF4 /* 't' -> */,
	/* pos 00aa:  58 */    0xEF /* 'o' -> */,
	/* pos 00ab:  59 */    0xE3 /* 'c' -> */,
	/* pos 00ac:  60 */    0xEF /* 'o' -> */,
	/* pos 00ad:  61 */    0xEC /* 'l' -> */,
	/* pos 00ae:  62 */    0xBA /* ':' -> */,
	/* pos 00af:  63 */    0x00, 0x07                  /* - terminal marker  7 - */,
	/* pos 00b1:  64 */    0xF0 /* 'p' -> */,
	/* pos 00b2:  65 */    0xE7 /* 'g' -> */,
	/* pos 00b3:  66 */    0xF2 /* 'r' -> */,
	/* pos 00b4:  67 */    0xE1 /* 'a' -> */,
	/* pos 00b5:  68 */    0xE4 /* 'd' -> */,
	/* pos 00b6:  69 */    0xE5 /* 'e' -> */,
	/* pos 00b7:  70 */    0xBA /* ':' -> */,
	/* pos 00b8:  71 */    0x00, 0x08                  /* - terminal marker  8 - */,
	/* pos 00ba:  72 */    0xE9 /* 'i' -> */,
	/* pos 00bb:  73 */    0xE7 /* 'g' -> */,
	/* pos 00bc:  74 */    0xE9 /* 'i' -> */,
	/* pos 00bd:  75 */    0xEE /* 'n' -> */,
	/* pos 00be:  76 */    0xBA /* ':' -> */,
	/* pos 00bf:  77 */    0x00, 0x09                  /* - terminal marker  9 - */,
	/* pos 00c1:  78 */    0xF2 /* 'r' -> */,
	/* pos 00c2:  79 */    0xE1 /* 'a' -> */,
	/* pos 00c3:  80 */    0xE6 /* 'f' -> */,
	/* pos 00c4:  81 */    0xF4 /* 't' -> */,
	/* pos 00c5:  82 */    0xBA /* ':' -> */,
	/* pos 00c6:  83 */    0x00, 0x0A                  /* - terminal marker 10 - */,
	/* pos 00c8:  84 */    0x8A /* '.' -> */,
	/* pos 00c9:  85 */    0x00, 0x0B                  /* - terminal marker 11 - */,
	/* pos 00cb:  86 */    0x00, 0x0C                  /* - terminal marker 12 - */,
	/* pos 00cd:  87 */    0xE5 /* 'e' -> */,
	/* pos 00ce:  88 */    0xF2 /* 'r' -> */,
	/* pos 00cf:  89 */    0xF3 /* 's' -> */,
	/* pos 00d0:  90 */    0xE9 /* 'i' -> */,
	/* pos 00d1:  91 */    0xEF /* 'o' -> */,
	/* pos 00d2:  92 */    0xEE /* 'n' -> */,
	/* pos 00d3:  93 */    0xBA /* ':' -> */,
	/* pos 00d4:  94 */    0x00, 0x0D                  /* - terminal marker 13 - */,
	/* pos 00d6:  95 */    0xF2 /* 'r' -> */,
	/* pos 00d7:  96 */    0xE9 /* 'i' -> */,
	/* pos 00d8:  97 */    0xE7 /* 'g' -> */,
	/* pos 00d9:  98 */    0xE9 /* 'i' -> */,
	/* pos 00da:  99 */    0xEE /* 'n' -> */,
	/* pos 00db: 100 */    0xBA /* ':' -> */,
	/* pos 00dc: 101 */    0x00, 0x0E                  /* - terminal marker 14 - */,
	/* pos 00de: 102 */    0xF8 /* 'x' -> */,
	/* pos 00df: 103 */    0xF4 /* 't' -> */,
	/* pos 00e0: 104 */    0xE5 /* 'e' -> */,
	/* pos 00e1: 105 */    0xEE /* 'n' -> */,
	/* pos 00e2: 106 */    0xF3 /* 's' -> */,
	/* pos 00e3: 107 */    0xE9 /* 'i' -> */,
	/* pos 00e4: 108 */    0xEF /* 'o' -> */,
	/* pos 00e5: 109 */    0xEE /* 'n' -> */,
	/* pos 00e6: 110 */    0xF3 /* 's' -> */,
	/* pos 00e7: 111 */    0xBA /* ':' -> */,
	/* pos 00e8: 112 */    0x00, 0x0F                  /* - terminal marker 15 - */,
	/* pos 00ea: 113 */    0xE3 /* 'c' -> */,
	/* pos 00eb: 114 */    0xE3 /* 'c' -> */,
	/* pos 00ec: 115 */    0xE5 /* 'e' -> */,
	/* pos 00ed: 116 */    0xF0 /* 'p' -> */,
	/* pos 00ee: 117 */    0xF4 /* 't' -> */,
	/* pos 00ef: 118 */    0xBA /* ':' -> */,
	/* pos 00f0: 119 */    0x00, 0x10                  /* - terminal marker 16 - */,
	/* pos 00f2: 120 */    0xEF /* 'o' -> */,
	/* pos 00f3: 121 */    0xEE /* 'n' -> */,
	/* pos 00f4: 122 */    0xE3 /* 'c' -> */,
	/* pos 00f5: 123 */    0xE5 /* 'e' -> */,
	/* pos 00f6: 124 */    0xBA /* ':' -> */,
	/* pos 00f7: 125 */    0x00, 0x11                  /* - terminal marker 17 - */,
	/* pos 00f9: 126 */    0xF4 /* 't' -> */,
	/* pos 00fa: 127 */    0xF0 /* 'p' -> */,
	/* pos 00fb: 128 */    0xAF /* '/' -> */,
	/* pos 00fc: 129 */    0xB1 /* '1' -> */,
	/* pos 00fd: 130 */    0xAE /* '.' -> */,
	/* pos 00fe: 131 */    0xB1 /* '1' -> */,
	/* pos 00ff: 132 */    0xA0 /* ' ' -> */,
	/* pos 0100: 133 */    0x00, 0x12                  /* - terminal marker 18 - */,
	/* pos 0102: 134 */    0x63 /* 'c' */, 0x07, 0x00  /* (to 0x0109 state 135) */,
	0x75 /* 'u' */, 0x88, 0x00  /* (to 0x018D state 235) */,
	0x08, /* fail */
	/* pos 0109: 135 */    0xE3 /* 'c' -> */,
	/* pos 010a: 136 */    0xE5 /* 'e' -> */,
	/* pos 010b: 137 */    0x70 /* 'p' */, 0x07, 0x00  /* (to 0x0112 state 138) */,
	0x73 /* 's' */, 0x0E, 0x00  /* (to 0x011C state 141) */,
	0x08, /* fail */
	/* pos 0112: 138 */    0xF4 /* 't' -> */,
	/* pos 0113: 139 */    0x3A /* ':' */, 0x07, 0x00  /* (to 0x011A state 140) */,
	0x2D /* '-' */, 0x47, 0x00  /* (to 0x015D state 197) */,
	0x08, /* fail */
	/* pos 011a: 140 */    0x00, 0x13                  /* - terminal marker 19 - */,
	/* pos 011c: 141 */    0xF3 /* 's' -> */,
	/* pos 011d: 142 */    0xAD /* '-' -> */,
	/* pos 011e: 143 */    0xE3 /* 'c' -> */,
	/* pos 011f: 144 */    0xEF /* 'o' -> */,
	/* pos 0120: 145 */    0xEE /* 'n' -> */,
	/* pos 0121: 146 */    0xF4 /* 't' -> */,
	/* pos 0122: 147 */    0xF2 /* 'r' -> */,
	/* pos 0123: 148 */    0xEF /* 'o' -> */,
	/* pos 0124: 149 */    0xEC /* 'l' -> */,
	/* pos 0125: 150 */    0xAD /* '-' -> */,
	/* pos 0126: 151 */    0xF2 /* 'r' -> */,
	/* pos 0127: 152 */    0xE5 /* 'e' -> */,
	/* pos 0128: 153 */    0xF1 /* 'q' -> */,
	/* pos 0129: 154 */    0xF5 /* 'u' -> */,
	/* pos 012a: 155 */    0xE5 /* 'e' -> */,
	/* pos 012b: 156 */    0xF3 /* 's' -> */,
	/* pos 012c: 157 */    0xF4 /* 't' -> */,
	/* pos 012d: 158 */    0xAD /* '-' -> */,
	/* pos 012e: 159 */    0xE8 /* 'h' -> */,
	/* pos 012f: 160 */    0xE5 /* 'e' -> */,
	/* pos 0130: 161 */    0xE1 /* 'a' -> */,
	/* pos 0131: 162 */    0xE4 /* 'd' -> */,
	/* pos 0132: 163 */    0xE5 /* 'e' -> */,
	/* pos 0133: 164 */    0xF2 /* 'r' -> */,
	/* pos 0134: 165 */    0xF3 /* 's' -> */,
	/* pos 0135: 166 */    0xBA /* ':' -> */,
	/* pos 0136: 167 */    0x00, 0x14                  /* - terminal marker 20 - */,
	/* pos 0138: 168 */    0xE6 /* 'f' -> */,
	/* pos 0139: 169 */    0xAD /* '-' -> */,
	/* pos 013a: 170 */    0x6D /* 'm' */, 0x07, 0x00  /* (to 0x0141 state 171) */,
	0x6E /* 'n' */, 0x14, 0x00  /* (to 0x0151 state 186) */,
	0x08, /* fail */
	/* pos 0141: 171 */    0xEF /* 'o' -> */,
	/* pos 0142: 172 */    0xE4 /* 'd' -> */,
	/* pos 0143: 173 */    0xE9 /* 'i' -> */,
	/* pos 0144: 174 */    0xE6 /* 'f' -> */,
	/* pos 0145: 175 */    0xE9 /* 'i' -> */,
	/* pos 0146: 176 */    0xE5 /* 'e' -> */,
	/* pos 0147: 177 */    0xE4 /* 'd' -> */,
	/* pos 0148: 178 */    0xAD /* '-' -> */,
	/* pos 0149: 179 */    0xF3 /* 's' -> */,
	/* pos 014a: 180 */    0xE9 /* 'i' -> */,
	/* pos 014b: 181 */    0xEE /* 'n' -> */,
	/* pos 014c: 182 */    0xE3 /* 'c' -> */,
	/* pos 014d: 183 */    0xE5 /* 'e' -> */,
	/* pos 014e: 184 */    0xBA /* ':' -> */,
	/* pos 014f: 185 */    0x00, 0x15                  /* - terminal marker 21 - */,
	/* pos 0151: 186 */    0xEF /* 'o' -> */,
	/* pos 0152: 187 */    0xEE /* 'n' -> */,
	/* pos 0153: 188 */    0xE5 /* 'e' -> */,
	/* pos 0154: 189 */    0xAD /* '-' -> */,
	/* pos 0155: 190 */    0xED /* 'm' -> */,
	/* pos 0156: 191 */    0xE1 /* 'a' -> */,
	/* pos 0157: 192 */    0xF4 /* 't' -> */,
	/* pos 0158: 193 */    0xE3 /* 'c' -> */,
	/* pos 0159: 194 */    0xE8 /* 'h' -> */,
	/* pos 015a: 195 */    0xBA /* ':' -> */,
	/* pos 015b: 196 */    0x00, 0x16                  /* - terminal marker 22 - */,
	/* pos 015d: 197 */    0x65 /* 'e' */, 0x07, 0x00  /* (to 0x0164 state 198) */,
	0x6C /* 'l' */, 0x0E, 0x00  /* (to 0x016E state 207) */,
	0x08, /* fail */
	/* pos 0164: 198 */    0xEE /* 'n' -> */,
	/* pos 0165: 199 */    0xE3 /* 'c' -> */,
	/* pos 0166: 200 */    0xEF /* 'o' -> */,
	/* pos 0167: 201 */    0xE4 /* 'd' -> */,
	/* pos 0168: 202 */    0xE9 /* 'i' -> */,
	/* pos 0169: 203 */    0xEE /* 'n' -> */,
	/* pos 016a: 204 */    0xE7 /* 'g' -> */,
	/* pos 016b: 205 */    0xBA /* ':' -> */,
	/* pos 016c: 206 */    0x00, 0x17                  /* - terminal marker 23 - */,
	/* pos 016e: 207 */    0xE1 /* 'a' -> */,
	/* pos 016f: 208 */    0xEE /* 'n' -> */,
	/* pos 0170: 209 */    0xE7 /* 'g' -> */,
	/* pos 0171: 210 */    0xF5 /* 'u' -> */,
	/* pos 0172: 211 */    0xE1 /* 'a' -> */,
	/* pos 0173: 212 */    0xE7 /* 'g' -> */,
	/* pos 0174: 213 */    0xE5 /* 'e' -> */,
	/* pos 0175: 214 */    0xBA /* ':' -> */,
	/* pos 0176: 215 */    0x00, 0x18                  /* - terminal marker 24 - */,
	/* pos 0178: 216 */    0xE1 /* 'a' -> */,
	/* pos 0179: 217 */    0xE7 /* 'g' -> */,
	/* pos 017a: 218 */    0xED /* 'm' -> */,
	/* pos 017b: 219 */    0xE1 /* 'a' -> */,
	/* pos 017c: 220 */    0xBA /* ':' -> */,
	/* pos 017d: 221 */    0x00, 0x19                  /* - terminal marker 25 - */,
	/* pos 017f: 222 */    0xE3 /* 'c' -> */,
	/* pos 0180: 223 */    0xE8 /* 'h' -> */,
	/* pos 0181: 224 */    0xE5 /* 'e' -> */,
	/* pos 0182: 225 */    0xAD /* '-' -> */,
	/* pos 0183: 226 */    0xE3 /* 'c' -> */,
	/* pos 0184: 227 */    0xEF /* 'o' -> */,
	/* pos 0185: 228 */    0xEE /* 'n' -> */,
	/* pos 0186: 229 */    0xF4 /* 't' -> */,
	/* pos 0187: 230 */    0xF2 /* 'r' -> */,
	/* pos 0188: 231 */    0xEF /* 'o' -> */,
	/* pos 0189: 232 */    0xEC /* 'l' -> */,
	/* pos 018a: 233 */    0xBA /* ':' -> */,
	/* pos 018b: 234 */    0x00, 0x1A                  /* - terminal marker 26 - */,
	/* pos 018d: 235 */    0xF4 /* 't' -> */,
	/* pos 018e: 236 */    0xE8 /* 'h' -> */,
	/* pos 018f: 237 */    0xEF /* 'o' -> */,
	/* pos 0190: 238 */    0xF2 /* 'r' -> */,
	/* pos 0191: 239 */    0xE9 /* 'i' -> */,
	/* pos 0192: 240 */    0xFA /* 'z' -> */,
	/* pos 0193: 241 */    0xE1 /* 'a' -> */,
	/* pos 0194: 242 */    0xF4 /* 't' -> */,
	/* pos 0195: 243 */    0xE9 /* 'i' -> */,
	/* pos 0196: 244 */    0xEF /* 'o' -> */,
	/* pos 0197: 245 */    0xEE /* 'n' -> */,
	/* pos 0198: 246 */    0xBA /* ':' -> */,
	/* pos 0199: 247 */    0x00, 0x1B                  /* - terminal marker 27 - */,
	/* pos 019b: 248 */    0xEB /* 'k' -> */,
	/* pos 019c: 249 */    0xE9 /* 'i' -> */,
	/* pos 019d: 250 */    0xE5 /* 'e' -> */,
	/* pos 019e: 251 */    0xBA /* ':' -> */,
	/* pos 019f: 252 */    0x00, 0x1C                  /* - terminal marker 28 - */,
	/* pos 01a1: 253 */    0xE5 /* 'e' -> */,
	/* pos 01a2: 254 */    0xEE /* 'n' -> */,
	/* pos 01a3: 255 */    0xF4 /* 't' -> */,
	/* pos 01a4: 256 */    0xAD /* '-' -> */,
	/* pos 01a5: 257 */    0x6C /* 'l' */, 0x07, 0x00  /* (to 0x01AC state 258) */,
	0x74 /* 't' */, 0x0C, 0x00  /* (to 0x01B4 state 265) */,
	0x08, /* fail */
	/* pos 01ac: 258 */    0xE5 /* 'e' -> */,
	/* pos 01ad: 259 */    0xEE /* 'n' -> */,
	/* pos 01ae: 260 */    0xE7 /* 'g' -> */,
	/* pos 01af: 261 */    0xF4 /* 't' -> */,
	/* pos 01b0: 262 */    0xE8 /* 'h' -> */,
	/* pos 01b1: 263 */    0xBA /* ':' -> */,
	/* pos 01b2: 264 */    0x00, 0x1D                  /* - terminal marker 29 - */,
	/* pos 01b4: 265 */    0xF9 /* 'y' -> */,
	/* pos 01b5: 266 */    0xF0 /* 'p' -> */,
	/* pos 01b6: 267 */    0xE5 /* 'e' -> */,
	/* pos 01b7: 268 */    0xBA /* ':' -> */,
	/* pos 01b8: 269 */    0x00, 0x1E                  /* - terminal marker 30 - */,
	/* pos 01ba: 270 */    0xE1 /* 'a' -> */,
	/* pos 01bb: 271 */    0xF4 /* 't' -> */,
	/* pos 01bc: 272 */    0xE5 /* 'e' -> */,
	/* pos 01bd: 273 */    0xBA /* ':' -> */,
	/* pos 01be: 274 */    0x00, 0x1F                  /* - terminal marker 31 - */,
	/* pos 01c0: 275 */    0x61 /* 'a' */, 0x07, 0x00  /* (to 0x01C7 state 276) */,
	0x65 /* 'e' */, 0x0A, 0x00  /* (to 0x01CD state 281) */,
	0x08, /* fail */
	/* pos 01c7: 276 */    0xEE /* 'n' -> */,
	/* pos 01c8: 277 */    0xE7 /* 'g' -> */,
	/* pos 01c9: 278 */    0xE5 /* 'e' -> */,
	/* pos 01ca: 279 */    0xBA /* ':' -> */,
	/* pos 01cb: 280 */    0x00, 0x20                  /* - terminal marker 32 - */,
	/* pos 01cd: 281 */    0xE6 /* 'f' -> */,
	/* pos 01ce: 282 */    0xE5 /* 'e' -> */,
	/* pos 01cf: 283 */    0xF2 /* 'r' -> */,
	/* pos 01d0: 284 */    0xE5 /* 'e' -> */,
	/* pos 01d1: 285 */    0xF2 /* 'r' -> */,
	/* pos 01d2: 286 */    0xBA /* ':' -> */,
	/* pos 01d3: 287 */    0x00, 0x21                  /* - terminal marker 33 - */,
	/* total size 469 bytes */

};

#define FAIL_CHAR 0x08

int lextable_decode(int pos, char c)
{

	c = tolower(c);

	while (1) {
		if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
			if ((lextable[pos] & 0x7f) != c)
				return -1;
			/* fall thru */
			pos++;
			if (lextable[pos] == FAIL_CHAR)
				return -1;
			return pos;
		}
		/* b7 = 0, end or 3-byte */
		if (lextable[pos] < FAIL_CHAR) /* terminal marker */
			return pos;

		if (lextable[pos] == c) /* goto */
			return pos + (lextable[pos + 1]) +
						(lextable[pos + 2] << 8);
		/* fall thru goto */
		pos += 3;
		/* continue */
	}
}

int lws_allocate_header_table(struct libwebsocket *wsi)
{
	wsi->u.hdr.ah = (allocated_headers*)malloc(sizeof(*wsi->u.hdr.ah));
	if (wsi->u.hdr.ah == NULL) {
		lwsl_err("Out of memory\n");
		return -1;
	}
	memset(wsi->u.hdr.ah->frag_index, 0, sizeof(wsi->u.hdr.ah->frag_index));
	wsi->u.hdr.ah->next_frag_index = 0;
	wsi->u.hdr.ah->pos = 0;

	return 0;
}

LWS_VISIBLE int lws_hdr_total_length(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return len;
}

LWS_VISIBLE int lws_hdr_copy(struct libwebsocket *wsi, char *dest, int len,
						enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;

	if (toklen >= len)
		return -1;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;

	do {
		strcpy(dest,
			&wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset]);
		dest += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return toklen;
}

char *lws_hdr_simple_ptr(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return NULL;

	return &wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset];
}

int lws_hdr_simple_create(struct libwebsocket *wsi,
				enum lws_token_indexes h, const char *s)
{
	wsi->u.hdr.ah->next_frag_index++;
	if (wsi->u.hdr.ah->next_frag_index ==
	       sizeof(wsi->u.hdr.ah->frags) / sizeof(wsi->u.hdr.ah->frags[0])) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->u.hdr.ah->frag_index[h] = wsi->u.hdr.ah->next_frag_index;

	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].next_frag_index =
									      0;

	do {
		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_err("Ran out of header data space\n");
			return -1;
		}
		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = *s;
		if (*s)
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len++;
	} while (*s++);

	return 0;
}

static char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static int issue_char(struct libwebsocket *wsi, unsigned char c)
{
	if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
		lwsl_warn("excessive header content\n");
		return -1;
	}

	if( wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len >= 
		wsi->u.hdr.current_token_limit) {
		lwsl_warn("header %i exceeds limit\n", wsi->u.hdr.parser_state);
		return 1;
	};

	wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
	if (c)
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;

	return 0;
}

int libwebsocket_parse(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->u.hdr.parser_state) {
	case WSI_TOKEN_GET_URI:
	case WSI_TOKEN_POST_URI:
	case WSI_TOKEN_OPTIONS_URI:
	case WSI_TOKEN_HOST:
	case WSI_TOKEN_CONNECTION:
	case WSI_TOKEN_KEY1:
	case WSI_TOKEN_KEY2:
	case WSI_TOKEN_PROTOCOL:
	case WSI_TOKEN_UPGRADE:
	case WSI_TOKEN_ORIGIN:
	case WSI_TOKEN_SWORIGIN:
	case WSI_TOKEN_DRAFT:
	case WSI_TOKEN_CHALLENGE:
	case WSI_TOKEN_KEY:
	case WSI_TOKEN_VERSION:
	case WSI_TOKEN_ACCEPT:
	case WSI_TOKEN_NONCE:
	case WSI_TOKEN_EXTENSIONS:
	case WSI_TOKEN_HTTP:
	case WSI_TOKEN_HTTP_ACCEPT:
	case WSI_TOKEN_HTTP_AC_REQUEST_HEADERS:
	case WSI_TOKEN_HTTP_IF_MODIFIED_SINCE:
	case WSI_TOKEN_HTTP_IF_NONE_MATCH:
	case WSI_TOKEN_HTTP_ACCEPT_ENCODING:
	case WSI_TOKEN_HTTP_ACCEPT_LANGUAGE:
	case WSI_TOKEN_HTTP_PRAGMA:
	case WSI_TOKEN_HTTP_CACHE_CONTROL:
	case WSI_TOKEN_HTTP_AUTHORIZATION:
	case WSI_TOKEN_HTTP_COOKIE:
	case WSI_TOKEN_HTTP_CONTENT_LENGTH:
	case WSI_TOKEN_HTTP_CONTENT_TYPE:
	case WSI_TOKEN_HTTP_DATE:
	case WSI_TOKEN_HTTP_RANGE:
	case WSI_TOKEN_HTTP_REFERER:


		lwsl_parser("WSI_TOK_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional initial space swallow */
		if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->frag_index[
				      wsi->u.hdr.parser_state]].len && c == ' ')
			break;

		if ((wsi->u.hdr.parser_state != WSI_TOKEN_GET_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_POST_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_OPTIONS_URI))
			goto check_eol;

		/* special URI processing... end at space */

		if (c == ' ') {
			/* enforce starting with / */
			if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len)
				if (issue_char(wsi, '/') < 0)
					return -1;
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			goto spill;
		}

		/* special URI processing... convert %xx */

		switch (wsi->u.hdr.ues) {
		case URIES_IDLE:
			if (c == '%') {
				wsi->u.hdr.ues = URIES_SEEN_PERCENT;
				goto swallow;
			}
			break;
		case URIES_SEEN_PERCENT:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				if (issue_char(wsi, '%') < 0)
					return -1;
				wsi->u.hdr.ues = URIES_IDLE;
				/* continue on to assess c */
				break;
			}
			wsi->u.hdr.esc_stash = c;
			wsi->u.hdr.ues = URIES_SEEN_PERCENT_H1;
			goto swallow;
			
		case URIES_SEEN_PERCENT_H1:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				issue_char(wsi, '%');
				wsi->u.hdr.ues = URIES_IDLE;
				/* regurgitate + assess */
				if (libwebsocket_parse(context, wsi, wsi->u.hdr.esc_stash) < 0)
					return -1;
				/* continue on to assess c */
				break;
			}
			c = (char_to_hex(wsi->u.hdr.esc_stash) << 4) |
					char_to_hex(c);
			wsi->u.hdr.ues = URIES_IDLE;
			break;
		}

		/*
		 * special URI processing... 
		 *  convert /.. or /... or /../ etc to /
		 *  convert /./ to /
		 *  convert // or /// etc to /
		 *  leave /.dir or whatever alone
		 */

		switch (wsi->u.hdr.ups) {
		case URIPS_IDLE:
			/* issue the first / always */
			if (c == '/')
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_SEEN_SLASH:
			/* swallow subsequent slashes */
			if (c == '/')
				goto swallow;
			/* track and swallow the first . after / */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT;
				goto swallow;
			} else
				wsi->u.hdr.ups = URIPS_IDLE;
			break;
		case URIPS_SEEN_SLASH_DOT:
			/* swallow second . */
			if (c == '.') {
				/* 
				 * back up one dir level if possible
				 * safe against header fragmentation because
				 * the method URI can only be in 1 fragment
				 */
				if (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 2) {
					wsi->u.hdr.ah->pos--;
					wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					do {
						wsi->u.hdr.ah->pos--;
						wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					} while (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 1 &&
							wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos] != '/');
				}
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT_DOT;
				goto swallow;
			}
			/* change /./ to / */
			if (c == '/') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				goto swallow;
			}
			/* it was like /.dir ... regurgitate the . */
			wsi->u.hdr.ups = URIPS_IDLE;
			issue_char(wsi, '.');
			break;
			
		case URIPS_SEEN_SLASH_DOT_DOT:
			/* swallow prior .. chars and any subsequent . */
			if (c == '.')
				goto swallow;
			/* last issued was /, so another / == // */
			if (c == '/')
				goto swallow;
			else /* last we issued was / so SEEN_SLASH */
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_ARGUMENTS:
			/* leave them alone */
			break;
		}

check_eol:

		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE &&
								  c == '\x0d') {
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			lwsl_parser("*\n");
		}

		if (c == '?') { /* start of URI arguments */
			/* seal off uri header */
			wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = '\0';

			/* move to using WSI_TOKEN_HTTP_URI_ARGS */
			wsi->u.hdr.ah->next_frag_index++;
			wsi->u.hdr.ah->frags[
				wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len = 0;
			wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

			wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] =
						 wsi->u.hdr.ah->next_frag_index;

			/* defeat normal uri path processing */
			wsi->u.hdr.ups = URIPS_ARGUMENTS;
			goto swallow;
		}

spill:
		{
			int issue_result = issue_char(wsi, c);
			if (issue_result < 0) {
				return -1;
			}
			else if(issue_result > 0) {
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			};
		};
swallow:
		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
			goto set_parsing_complete;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		lwsl_parser("WSI_TOKEN_NAME_PART '%c'\n", c);

		wsi->u.hdr.lextable_pos =
				lextable_decode(wsi->u.hdr.lextable_pos, c);

		if (wsi->u.hdr.lextable_pos < 0) {
			/* this is not a header we know about */
			if (wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP]) {
				/*
				 * altready had the method, no idea what
				 * this crap is, ignore
				 */
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			/*
			 * hm it's an unknown http method in fact,
			 * treat as dangerous
			 */

			lwsl_info("Unknown method - dropping\n");
			return -1;
		}
		if (lextable[wsi->u.hdr.lextable_pos] < FAIL_CHAR) {

			/* terminal state */

			n = (lextable[wsi->u.hdr.lextable_pos] << 8) | lextable[wsi->u.hdr.lextable_pos + 1];

			lwsl_parser("known hdr %d\n", n);
			if (n == WSI_TOKEN_GET_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI]) {
				lwsl_warn("Duplicated GET\n");
				return -1;
			} else if (n == WSI_TOKEN_POST_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI]) {
				lwsl_warn("Duplicated POST\n");
				return -1;
			} else if (n == WSI_TOKEN_OPTIONS_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI]) {
				lwsl_warn("Duplicated OPTIONS\n");
				return -1;
			}

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->u.hdr.parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);

			if( context->token_limits ) {
				wsi->u.hdr.current_token_limit = \
					context->token_limits->token_limit[wsi->u.hdr.parser_state];
			}
			else {
				wsi->u.hdr.current_token_limit = sizeof(wsi->u.hdr.ah->data);
			};

			if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;

			goto start_fragment;
		}
		break;

start_fragment:
		wsi->u.hdr.ah->next_frag_index++;
		if (wsi->u.hdr.ah->next_frag_index ==
				sizeof(wsi->u.hdr.ah->frags) /
					      sizeof(wsi->u.hdr.ah->frags[0])) {
			lwsl_warn("More hdr frags than we can deal with\n");
			return -1;
		}

		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
		wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

		n = wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state];
		if (!n) { /* first fragment */
			wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state] =
						 wsi->u.hdr.ah->next_frag_index;
			break;
		}
		/* continuation */
		while (wsi->u.hdr.ah->frags[n].next_frag_index)
				n = wsi->u.hdr.ah->frags[n].next_frag_index;
		wsi->u.hdr.ah->frags[n].next_frag_index =
						 wsi->u.hdr.ah->next_frag_index;

		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_warn("excessive header content\n");
			return -1;
		}

		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = ' ';
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;
		break;

		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
		lwsl_parser("WSI_TOKEN_SKIPPING '%c'\n", c);

		if (c == '\x0d')
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;

	case WSI_TOKEN_SKIPPING_SAW_CR:
		lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a') {
			wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.hdr.lextable_pos = 0;
		} else
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
		break;
		/* we're done, ignore anything else */

	case WSI_PARSING_COMPLETE:
		lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
		break;

	default:	/* keep gcc happy */
		break;
	}

	return 0;

set_parsing_complete:

	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		lwsl_parser("v%02d hdrs completed\n", wsi->ietf_spec_revision);
	}
	wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return 0;
}


/**
 * lws_frame_is_binary: true if the current frame was sent in binary mode
 *
 * @wsi: the connection we are inquiring about
 *
 * This is intended to be called from the LWS_CALLBACK_RECEIVE callback if
 * it's interested to see if the frame it's dealing with was sent in binary
 * mode.
 */

LWS_VISIBLE int lws_frame_is_binary(struct libwebsocket *wsi)
{
	return wsi->u.ws.frame_is_binary;
}

int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	struct lws_tokens eff_buf;
	int ret = 0;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:

		switch (wsi->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->u.ws.all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_rx_sm: unknown spec version %d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_MASK_NONCE_1:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_2;
		break;
	case LWS_RXPS_04_MASK_NONCE_2:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_3;
		break;
	case LWS_RXPS_04_MASK_NONCE_3:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->u.ws.frame_mask_index = 0;

		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_1;
		break;

	/*
	 *  04 logical framing from the spec (all this is masked when incoming
	 *  and has to be unmasked)
	 *
	 * We ignore the possibility of extension data because we don't
	 * negotiate any extensions at the moment.
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-------+-+-------------+-------------------------------+
	 *   |F|R|R|R| opcode|R| Payload len |    Extended payload length    |
	 *   |I|S|S|S|  (4)  |S|     (7)     |             (16/63)           |
	 *   |N|V|V|V|       |V|             |   (if payload len==126/127)   |
	 *   | |1|2|3|       |4|             |                               |
	 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 *   |     Extended payload length continued, if payload len == 127  |
	 *   + - - - - - - - - - - - - - - - +-------------------------------+
	 *   |                               |         Extension data        |
	 *   +-------------------------------+ - - - - - - - - - - - - - - - +
	 *   :                                                               :
	 *   +---------------------------------------------------------------+
	 *   :                       Application data                        :
	 *   +---------------------------------------------------------------+
	 *
	 *  We pass payload through to userland as soon as we get it, ignoring
	 *  FIN.  It's up to userland to buffer it up if it wants to see a
	 *  whole unfragmented block of the original size (which may be up to
	 *  2^63 long!)
	 */

	case LWS_RXPS_04_FRAME_HDR_1:
handle_first:

		wsi->u.ws.opcode = c & 0xf;
		wsi->u.ws.rsv = c & 0x70;
		wsi->u.ws.final = !!((c >> 7) & 1);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			wsi->u.ws.frame_is_binary =
			     wsi->u.ws.opcode == LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		}
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		wsi->u.ws.this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->u.ws.rx_packet_length = c & 0x7f;
			if (wsi->u.ws.this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->u.ws.rx_packet_length)
					wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
				else {
					wsi->lws_rx_parse_state = LWS_RXPS_NEW;
					goto spill;
				}
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		wsi->u.ws.rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->u.ws.rx_packet_length |= c;
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (c & 0x80) {
			lwsl_warn("b63 of length must be zero\n");
			/* kill the connection */
			return -1;
		}
#if defined __LP64__
		wsi->u.ws.rx_packet_length = ((size_t)c) << 56;
#else
		wsi->u.ws.rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->u.ws.rx_packet_length |= ((size_t)c);
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->u.ws.frame_masking_nonce_04[0] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->u.ws.frame_mask_index = 0;
		if (wsi->u.ws.rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:

		if (!wsi->u.ws.rx_user_buffer)
			lwsl_err("NULL user buffer...\n");

		if (wsi->u.ws.all_zero_nonce)
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] = c;
		else
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] =
				   c ^ wsi->u.ws.frame_masking_nonce_04[
					    (wsi->u.ws.frame_mask_index++) & 3];

		if (--wsi->u.ws.rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to LWS_MAX_SOCKET_IO_BUF
		 */

		if (!wsi->protocol->rx_buffer_size &&
			 		wsi->u.ws.rx_user_buffer_head !=
			 				  LWS_MAX_SOCKET_IO_BUF)
			break;
		else
			if (wsi->protocol->rx_buffer_size &&
					wsi->u.ws.rx_user_buffer_head !=
						  wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__CLOSE:
			/* is this an acknowledgement of our close? */
			if (wsi->state == WSI_STATE_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen client close ack\n");
				return -1;
			}
			lwsl_parser("server sees client close packet\n");
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
				&wsi->u.ws.rx_user_buffer[
					LWS_SEND_BUFFER_PRE_PADDING],
					wsi->u.ws.rx_user_buffer_head,
							       LWS_WRITE_CLOSE);
			if (n < 0)
				lwsl_info("write of close ack failed %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->u.ws.rx_user_buffer_head);
			lwsl_hexdump(&wsi->u.ws.rx_user_buffer[
					LWS_SEND_BUFFER_PRE_PADDING],
						 wsi->u.ws.rx_user_buffer_head);
			/* parrot the ping packet payload back as a pong */
			n = libwebsocket_write(wsi, (unsigned char *)
			&wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				 wsi->u.ws.rx_user_buffer_head, LWS_WRITE_PONG);
			if (n < 0)
				return -1;
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__PONG:
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
		case LWS_WS_OPCODE_07__CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
							wsi->u.ws.opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->u.ws.rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;

			if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX,
					&eff_buf, 0) <= 0) /* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
							      wsi->u.ws.opcode);

			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using libwebsocket_write
		 */

		eff_buf.token = &wsi->u.ws.rx_user_buffer[
						LWS_SEND_BUFFER_PRE_PADDING];
		eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;
		
		if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_PAYLOAD_RX, &eff_buf, 0) < 0)
			return -1;

		if (eff_buf.token_len > 0) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback)
				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi->protocol->owning_server,
						wsi, LWS_CALLBACK_RECEIVE,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
		    else
			    lwsl_err("No callback on payload spill!\n");
		}

		wsi->u.ws.rx_user_buffer_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
}


/**
 * libwebsockets_remaining_packet_payload() - Bytes to come before "overall"
 *					      rx packet is complete
 * @wsi:		Websocket instance (available from user callback)
 *
 *	This function is intended to be called from the callback if the
 *  user code is interested in "complete packets" from the client.
 *  libwebsockets just passes through payload as it comes and issues a buffer
 *  additionally when it hits a built-in limit.  The LWS_CALLBACK_RECEIVE
 *  callback handler can use this API to find out if the buffer it has just
 *  been given is the last piece of a "complete packet" from the client --
 *  when that is the case libwebsockets_remaining_packet_payload() will return
 *  0.
 *
 *  Many protocols won't care becuse their packets are always small.
 */

LWS_VISIBLE size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi)
{
	return wsi->u.ws.rx_packet_length;
}

/***************************************************
 * external/libwebsockets/src/pollfd.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

int
insert_wsi_socket_into_fds(struct libwebsocket_context *context,
						       struct libwebsocket *wsi)
{
	struct libwebsocket_pollargs pa = { wsi->sock, LWS_POLLIN, 0 };

	if (context->fds_count >= context->max_fds) {
		lwsl_err("Too many fds (%d)\n", context->max_fds);
		return 1;
	}

	if (wsi->sock >= context->max_fds) {
		lwsl_err("Socket fd %d is too high (%d)\n",
						wsi->sock, context->max_fds);
		return 1;
	}

	assert(wsi);
	assert(wsi->sock >= 0);

	lwsl_info("insert_wsi_socket_into_fds: wsi=%p, sock=%d, fds pos=%d\n",
					    wsi, wsi->sock, context->fds_count);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL,
		wsi->user_space, (void *) &pa, 0);

	context->lws_lookup[wsi->sock] = wsi;
	wsi->position_in_fds_table = context->fds_count;
	context->fds[context->fds_count].fd = wsi->sock;
	context->fds[context->fds_count].events = LWS_POLLIN;
	
	lws_plat_insert_socket_into_fds(context, wsi);

	/* external POLL support via protocol 0 */
	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_ADD_POLL_FD,
		wsi->user_space, (void *) &pa, 0);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_UNLOCK_POLL,
		wsi->user_space, (void *)&pa, 0);

	return 0;
}

int
remove_wsi_socket_from_fds(struct libwebsocket_context *context,
						      struct libwebsocket *wsi)
{
	int m;
	struct libwebsocket_pollargs pa = { wsi->sock, 0, 0 };

	lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE);

	if (!--context->fds_count) {
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_LOCK_POLL,
			wsi->user_space, (void *) &pa, 0);
		goto do_ext;
	}

	if (wsi->sock > context->max_fds) {
		lwsl_err("Socket fd %d too high (%d)\n",
						   wsi->sock, context->max_fds);
		return 1;
	}

	lwsl_info("%s: wsi=%p, sock=%d, fds pos=%d\n", __func__,
				    wsi, wsi->sock, wsi->position_in_fds_table);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL,
		wsi->user_space, (void *)&pa, 0);

	m = wsi->position_in_fds_table; /* replace the contents for this */

	/* have the last guy take up the vacant slot */
	context->fds[m] = context->fds[context->fds_count];

	lws_plat_delete_socket_from_fds(context, wsi, m);

	/*
	 * end guy's fds_lookup entry remains unchanged
	 * (still same fd pointing to same wsi)
	 */
	/* end guy's "position in fds table" changed */
	context->lws_lookup[context->fds[context->fds_count].fd]->
						position_in_fds_table = m;
	/* deletion guy's lws_lookup entry needs nuking */
	context->lws_lookup[wsi->sock] = NULL;
	/* removed wsi has no position any more */
	wsi->position_in_fds_table = -1;

do_ext:
	/* remove also from external POLL support via protocol 0 */
	if (wsi->sock) {
		context->protocols[0].callback(context, wsi,
		    LWS_CALLBACK_DEL_POLL_FD, wsi->user_space,
		    (void *) &pa, 0);
	}
	context->protocols[0].callback(context, wsi,
				       LWS_CALLBACK_UNLOCK_POLL,
				       wsi->user_space, (void *) &pa, 0);
	return 0;
}

int
lws_change_pollfd(struct libwebsocket *wsi, int _and, int _or)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;
	int tid;
	int sampled_tid;
	struct libwebsocket_pollfd *pfd;
	struct libwebsocket_pollargs pa;

	pfd = &context->fds[wsi->position_in_fds_table];
	pa.fd = wsi->sock;

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL, wsi->user_space,  (void *) &pa, 0);

	pa.prev_events = pfd->events;
	pa.events = pfd->events = (pfd->events & ~_and) | _or;

	context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CHANGE_MODE_POLL_FD,
				wsi->user_space, (void *) &pa, 0);

	/*
	 * if we changed something in this pollfd...
	 *   ... and we're running in a different thread context
	 *     than the service thread...
	 *       ... and the service thread is waiting ...
	 *         then cancel it to force a restart with our changed events
	 */
	if (pa.prev_events != pa.events) {
		
		if (lws_plat_change_pollfd(context, wsi, pfd)) {
			lwsl_info("%s failed\n", __func__);
			return 1;
		}

		sampled_tid = context->service_tid;
		if (sampled_tid) {
			tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
			if (tid != sampled_tid)
				libwebsocket_cancel_service(context);
		}
	}

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_UNLOCK_POLL, wsi->user_space, (void *) &pa, 0);
	
	return 0;
}


/**
 * libwebsocket_callback_on_writable() - Request a callback when this socket
 *					 becomes able to be written to without
 *					 blocking
 *
 * @context:	libwebsockets context
 * @wsi:	Websocket connection instance to get callback for
 */

LWS_VISIBLE int
libwebsocket_callback_on_writable(struct libwebsocket_context *context,
						      struct libwebsocket *wsi)
{
	if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_REQUEST_ON_WRITEABLE, NULL, 0))
		return 1;

	if (wsi->position_in_fds_table < 0) {
		lwsl_err("%s: failed to find socket %d\n", __func__, wsi->sock);
		return -1;
	}

	if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
		return -1;

	lws_libev_io(context, wsi, LWS_EV_START | LWS_EV_WRITE);

	return 1;
}

/**
 * libwebsocket_callback_on_writable_all_protocol() - Request a callback for
 *			all connections using the given protocol when it
 *			becomes possible to write to each socket without
 *			blocking in turn.
 *
 * @protocol:	Protocol whose connections will get callbacks
 */

LWS_VISIBLE int
libwebsocket_callback_on_writable_all_protocol(
				  const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			libwebsocket_callback_on_writable(context, wsi);
	}

	return 0;
}

/***************************************************
 * external/libwebsockets/src/server.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */


#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

int lws_context_init_server(struct lws_context_creation_info *info,
			    struct libwebsocket_context *context)
{
	int n;
	int sockfd;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int opt = 1;
	struct libwebsocket *wsi;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
	struct sockaddr_in serv_addr4;
	struct sockaddr *v;

	/* set up our external listening socket we serve on */

	if (info->port == CONTEXT_PORT_NO_LISTEN)
		return 0;

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context))
		sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
#endif
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		lwsl_err("ERROR opening socket\n");
		return 1;
	}

	/*
	 * allow us to restart even if old sockets in TIME_WAIT
	 */
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
				      (const char *)&opt, sizeof(opt));

	lws_plat_set_socket_options(context, sockfd);

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {
		v = (struct sockaddr *)&serv_addr6;
		n = sizeof(struct sockaddr_in6);
		bzero((char *) &serv_addr6, sizeof(serv_addr6));
		serv_addr6.sin6_addr = in6addr_any;
		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(info->port);
	} else
#endif
	{
		v = (struct sockaddr *)&serv_addr4;
		n = sizeof(serv_addr4);
		bzero((char *) &serv_addr4, sizeof(serv_addr4));
		serv_addr4.sin_addr.s_addr = INADDR_ANY;
		serv_addr4.sin_family = AF_INET;

		if (info->iface) {
			if (interface_to_sa(context, info->iface,
				   (struct sockaddr_in *)v, n) < 0) {
				lwsl_err("Unable to find interface %s\n",
							info->iface);
				compatible_close(sockfd);
				return 1;
			}
		}

		serv_addr4.sin_port = htons(info->port);
	} /* ipv4 */

	n = bind(sockfd, v, n);
	if (n < 0) {
		lwsl_err("ERROR on binding to port %d (%d %d)\n",
					      info->port, n, LWS_ERRNO);
		compatible_close(sockfd);
		return 1;
	}
	
	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
	else
		info->port = ntohs(sin.sin_port);

	context->listen_port = info->port;

	wsi = (struct libwebsocket *)malloc(sizeof(struct libwebsocket));
	if (wsi == NULL) {
		lwsl_err("Out of mem\n");
		compatible_close(sockfd);
		return 1;
	}
	memset(wsi, 0, sizeof(struct libwebsocket));
	wsi->sock = sockfd;
	wsi->mode = LWS_CONNMODE_SERVER_LISTENER;

	insert_wsi_socket_into_fds(context, wsi);

	context->listen_service_modulo = LWS_LISTEN_SERVICE_MODULO;
	context->listen_service_count = 0;
	context->listen_service_fd = sockfd;

	listen(sockfd, LWS_SOMAXCONN);
	lwsl_notice(" Listening on port %d\n", info->port);
	
	return 0;
}

int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;

	/* there is no pending change */
	if (!(wsi->u.ws.rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE))
		return 0;

	/* stuff is still buffered, not ready to really accept new input */
	if (wsi->u.ws.rxflow_buffer) {
		/* get ourselves called back to deal with stashed buffer */
		libwebsocket_callback_on_writable(context, wsi);
		return 0;
	}

	/* pending is cleared, we can change rxflow state */

	wsi->u.ws.rxflow_change_to &= ~LWS_RXFLOW_PENDING_CHANGE;

	lwsl_info("rxflow: wsi %p change_to %d\n", wsi,
			      wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: fail\n", __func__);
			return -1;
		}
	} else
		if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
			return -1;

	return 0;
}


int lws_handshake_server(struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char **buf, size_t len)
{
	struct allocated_headers *ah;
	char *uri_ptr = NULL;
	int uri_len = 0;
	char content_length_str[32];
	int n;

	/* LWS_CONNMODE_WS_SERVING */

	while (len--) {
		if (libwebsocket_parse(context, wsi, *(*buf)++)) {
			lwsl_info("libwebsocket_parse failed\n");
			goto bail_nuke_ah;
		}

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
			continue;

		lwsl_parser("libwebsocket_parse sees parsing complete\n");

		wsi->mode = LWS_CONNMODE_PRE_WS_SERVING_ACCEPT;
		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* is this websocket protocol or normal http 1.0? */

		if (!lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE) ||
			     !lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION)) {

			/* it's not websocket.... shall we accept it as http? */

			if (!lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) &&
				!lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) &&
				!lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI)) {
				lwsl_warn("Missing URI in HTTP request\n");
				goto bail_nuke_ah;
			}

			if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) &&
				lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				lwsl_warn("GET and POST methods?\n");
				goto bail_nuke_ah;
			}

			if (libwebsocket_ensure_user_space(wsi))
				goto bail_nuke_ah;

			if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) {
				uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI);
				uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
				lwsl_info("HTTP GET request for '%s'\n",
				    lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI));

			}
			if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				lwsl_info("HTTP POST request for '%s'\n",
				   lws_hdr_simple_ptr(wsi, WSI_TOKEN_POST_URI));
				uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_POST_URI);
				uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI);
			}
			if (lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI)) {
				lwsl_info("HTTP OPTIONS request for '%s'\n",
				   lws_hdr_simple_ptr(wsi, WSI_TOKEN_OPTIONS_URI));
				uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_OPTIONS_URI);
				uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI);
			}

			/*
			 * Hm we still need the headers so the
			 * callback can look at leaders like the URI, but we
			 * need to transition to http union state.... hold a
			 * copy of u.hdr.ah and deallocate afterwards
			 */
			ah = wsi->u.hdr.ah;

			/* union transition */
			memset(&wsi->u, 0, sizeof(wsi->u));
			wsi->mode = LWS_CONNMODE_HTTP_SERVING_ACCEPTED;
			wsi->state = WSI_STATE_HTTP;
			wsi->u.http.fd = LWS_INVALID_FILE;

			/* expose it at the same offset as u.hdr */
			wsi->u.http.ah = ah;

			/* HTTP header had a content length? */

			wsi->u.http.content_length = 0;
			if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
				wsi->u.http.content_length = 100 * 1024 * 1024;

			if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
				lws_hdr_copy(wsi, content_length_str,
						sizeof(content_length_str) - 1,
								WSI_TOKEN_HTTP_CONTENT_LENGTH);
				wsi->u.http.content_length = atoi(content_length_str);
			}

			if (wsi->u.http.content_length > 0) {
				wsi->u.http.body_index = 0;
				n = wsi->protocol->rx_buffer_size;
				if (!n)
					n = LWS_MAX_SOCKET_IO_BUF;
				wsi->u.http.post_buffer = (unsigned char*)malloc(n);
				if (!wsi->u.http.post_buffer) {
					lwsl_err("Unable to allocate post buffer\n");
					n = -1;
					goto cleanup;
				}
			}

			n = 0;
			if (wsi->protocol->callback)
				n = wsi->protocol->callback(context, wsi,
					LWS_CALLBACK_FILTER_HTTP_CONNECTION,
					     wsi->user_space, uri_ptr, uri_len);

			if (!n) {
				/*
				 * if there is content supposed to be coming,
				 * put a timeout on it having arrived
				 */
				libwebsocket_set_timeout(wsi,
					PENDING_TIMEOUT_HTTP_CONTENT,
							      AWAITING_TIMEOUT);

				if (wsi->protocol->callback)
					n = wsi->protocol->callback(context, wsi,
					    LWS_CALLBACK_HTTP,
					    wsi->user_space, uri_ptr, uri_len);
			}

cleanup:
			/* now drop the header info we kept a pointer to */
			if (ah)
				free(ah);
			/* not possible to continue to use past here */
			wsi->u.http.ah = NULL;

			if (n) {
				lwsl_info("LWS_CALLBACK_HTTP closing\n");
				return 1; /* struct ah ptr already nuked */
			}

			/*
			 * (if callback didn't start sending a file)
			 * deal with anything else as body, whether
			 * there was a content-length or not
			 */

			if (wsi->state != WSI_STATE_HTTP_ISSUING_FILE)
				wsi->state = WSI_STATE_HTTP_BODY;
			return 2; /* goto http_postbody; */
		}

		if (!wsi->protocol)
			lwsl_err("NULL protocol at libwebsocket_read\n");

		/*
		 * It's websocket
		 *
		 * Make sure user side is happy about protocol
		 */

		while (wsi->protocol->callback) {

			if (!lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL)) {
				if (wsi->protocol->name == NULL)
					break;
			} else
				if (wsi->protocol->name && strcmp(
					lws_hdr_simple_ptr(wsi,
						WSI_TOKEN_PROTOCOL),
						      wsi->protocol->name) == 0)
					break;

			wsi->protocol++;
		}

		/* we didn't find a protocol he wanted? */

		if (wsi->protocol->callback == NULL) {
			if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL) ==
									 NULL) {
				lwsl_info("no protocol -> prot 0 handler\n");
				wsi->protocol = &context->protocols[0];
			} else {
				lwsl_err("Req protocol %s not supported\n",
				   lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL));
				goto bail_nuke_ah;
			}
		}

		/* allocate wsi->user storage */
		if (libwebsocket_ensure_user_space(wsi))
			goto bail_nuke_ah;

		/*
		 * Give the user code a chance to study the request and
		 * have the opportunity to deny it
		 */

		if ((wsi->protocol->callback)(wsi->protocol->owning_server, wsi,
				LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
				wsi->user_space,
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL), 0)) {
			lwsl_warn("User code denied connection\n");
			goto bail_nuke_ah;
		}


		/*
		 * Perform the handshake according to the protocol version the
		 * client announced
		 */

		switch (wsi->ietf_spec_revision) {
		case 13:
			lwsl_parser("lws_parse calling handshake_04\n");
			if (handshake_0405(context, wsi)) {
				lwsl_info("hs0405 has failed the connection\n");
				goto bail_nuke_ah;
			}
			break;

		default:
			lwsl_warn("Unknown client spec version %d\n",
						       wsi->ietf_spec_revision);
			goto bail_nuke_ah;
		}

		/* drop the header info -- no bail_nuke_ah after this */

		if (wsi->u.hdr.ah)
			free(wsi->u.hdr.ah);

		wsi->mode = LWS_CONNMODE_WS_SERVING;

		/* union transition */
		memset(&wsi->u, 0, sizeof(wsi->u));
		wsi->u.ws.rxflow_change_to = LWS_RXFLOW_ALLOW;

		/*
		 * create the frame buffer for this connection according to the
		 * size mentioned in the protocol definition.  If 0 there, use
		 * a big default for compatibility
		 */

		n = wsi->protocol->rx_buffer_size;
		if (!n)
			n = LWS_MAX_SOCKET_IO_BUF;
		n += LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING;
		wsi->u.ws.rx_user_buffer = (char*)malloc(n);
		if (!wsi->u.ws.rx_user_buffer) {
			lwsl_err("Out of Mem allocating rx buffer %d\n", n);
			return 1;
		}
		lwsl_info("Allocating RX buffer %d\n", n);

		if (setsockopt(wsi->sock, SOL_SOCKET, SO_SNDBUF, (const char *)&n, sizeof n)) {
			lwsl_warn("Failed to set SNDBUF to %d", n);
			return 1;
		}

		lwsl_parser("accepted v%02d connection\n",
						       wsi->ietf_spec_revision);
	} /* while all chars are handled */

	return 0;

bail_nuke_ah:
	/* drop the header info */
	if (wsi->u.hdr.ah)
		free(wsi->u.hdr.ah);
	return 1;
}

struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context)
{
	struct libwebsocket *new_wsi;

	new_wsi = (struct libwebsocket *)malloc(sizeof(struct libwebsocket));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	memset(new_wsi, 0, sizeof(struct libwebsocket));
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;

	/* intialize the instance struct */

	new_wsi->state = WSI_STATE_HTTP;
	new_wsi->mode = LWS_CONNMODE_HTTP_SERVING;
	new_wsi->hdr_parsing_completed = 0;

	if (lws_allocate_header_table(new_wsi)) {
		free(new_wsi);
		return NULL;
	}

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;
	new_wsi->ietf_spec_revision = 0;

	/*
	 * outermost create notification for wsi
	 * no user_space because no protocol selection
	 */
	context->protocols[0].callback(context, new_wsi,
			LWS_CALLBACK_WSI_CREATE, NULL, NULL, 0);

	return new_wsi;
}

int lws_server_socket_service(struct libwebsocket_context *context,
			struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd)
{
	struct libwebsocket *new_wsi = NULL;
	int accept_fd = 0;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	int n;
	int len;

	switch (wsi->mode) {

	case LWS_CONNMODE_HTTP_SERVING:
	case LWS_CONNMODE_HTTP_SERVING_ACCEPTED:

		/* handle http headers coming in */

		/* pending truncated sends have uber priority */

		if (wsi->truncated_send_malloc) {
			if (pollfd->revents & LWS_POLLOUT)
				if (lws_issue_raw(wsi, wsi->truncated_send_malloc +
					wsi->truncated_send_offset,
							wsi->truncated_send_len) < 0) {
					lwsl_info("closing from socket service\n");
					return -1;
				}
			/*
			 * we can't afford to allow input processing send
			 * something new, so spin around he event loop until
			 * he doesn't have any partials
			 */
			break;
		}

		/* any incoming data ready? */

		if (pollfd->revents & LWS_POLLIN) {
			len = lws_ssl_capable_read(wsi,
					context->service_buffer,
						       sizeof(context->service_buffer));
			switch (len) {
			case 0:
				lwsl_info("lws_server_skt_srv: read 0 len\n");
				/* lwsl_info("   state=%d\n", wsi->state); */
				if (!wsi->hdr_parsing_completed)
					free(wsi->u.hdr.ah);
				/* fallthru */
			case LWS_SSL_CAPABLE_ERROR:
				libwebsocket_close_and_free_session(
						context, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
				return 0;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				break;
			}

			/* just ignore incoming if waiting for close */
			if (wsi->state != WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			
				/* hm this may want to send (via HTTP callback for example) */

				n = libwebsocket_read(context, wsi,
							context->service_buffer, len);
				if (n < 0)
					/* we closed wsi */
					return 0;

				/* hum he may have used up the writability above */
				break;
			}
		}

		/* this handles POLLOUT for http serving fragments */

		if (!(pollfd->revents & LWS_POLLOUT))
			break;

		/* one shot */
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			goto fail;
		
		lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_WRITE);

		if (wsi->state != WSI_STATE_HTTP_ISSUING_FILE) {
			n = user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi->protocol->owning_server,
					wsi, LWS_CALLBACK_HTTP_WRITEABLE,
					wsi->user_space,
					NULL,
					0);
			if (n < 0)
				libwebsocket_close_and_free_session(
				       context, wsi, LWS_CLOSE_STATUS_NOSTATUS);
			break;
		}

		/* nonzero for completion or error */
		if (libwebsockets_serve_http_file_fragment(context, wsi))
			libwebsocket_close_and_free_session(context, wsi,
					       LWS_CLOSE_STATUS_NOSTATUS);
		break;

	case LWS_CONNMODE_SERVER_LISTENER:

		/* pollin means a client has connected to us then */

		if (!(pollfd->revents & LWS_POLLIN))
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		lws_latency_pre(context, wsi);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		lws_latency(context, wsi,
			"unencrypted accept LWS_CONNMODE_SERVER_LISTENER",
						     accept_fd, accept_fd >= 0);
		if (accept_fd < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK) {
				lwsl_debug("accept asks to try again\n");
				break;
			}
			lwsl_warn("ERROR on accept: %s\n", strerror(LWS_ERRNO));
			break;
		}

		lws_plat_set_socket_options(context, accept_fd);

		/*
		 * look at who we connected to and give user code a chance
		 * to reject based on client IP.  There's no protocol selected
		 * yet so we issue this to protocols[0]
		 */

		if ((context->protocols[0].callback)(context, wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					   NULL, (void *)(long)accept_fd, 0)) {
			lwsl_debug("Callback denied network connection\n");
			compatible_close(accept_fd);
			break;
		}

		new_wsi = libwebsocket_create_new_server_wsi(context);
		if (new_wsi == NULL) {
			compatible_close(accept_fd);
			break;
		}

		new_wsi->sock = accept_fd;

		/* the transport is accepted... give him time to negotiate */
		libwebsocket_set_timeout(new_wsi,
			PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
							AWAITING_TIMEOUT);

		/*
		 * A new connection was accepted. Give the user a chance to
		 * set properties of the newly created wsi. There's no protocol
		 * selected yet so we issue this to protocols[0]
		 */

		(context->protocols[0].callback)(context, new_wsi,
			LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, NULL, NULL, 0);

		lws_libev_accept(context, new_wsi, accept_fd);

		if (!LWS_SSL_ENABLED(context)) {
			lwsl_debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

			insert_wsi_socket_into_fds(context, new_wsi);
		}
		break;

	default:
		break;
	}

	if (lws_server_socket_service_ssl(context, &wsi, new_wsi, accept_fd, pollfd))
		goto fail;

	return 0;
	
fail:
	libwebsocket_close_and_free_session(context, wsi,
						 LWS_CLOSE_STATUS_NOSTATUS);
	return 1;
}


static const char *err400[] = {
	"Bad Request",
	"Unauthorized",
	"Payment Required",
	"Forbidden",
	"Not Found",
	"Method Not Allowed",
	"Not Acceptable",
	"Proxy Auth Required",
	"Request Timeout",
	"Conflict",
	"Gone",
	"Length Required",
	"Precondition Failed",
	"Request Entity Too Large",
	"Request URI too Long",
	"Unsupported Media Type",
	"Requested Range Not Satisfiable",
	"Expectation Failed"
};

static const char *err500[] = {
	"Internal Server Error",
	"Not Implemented",
	"Bad Gateway",
	"Service Unavailable",
	"Gateway Timeout",
	"HTTP Version Not Supported"
};

/**
 * libwebsockets_return_http_status() - Return simple http status
 * @context:		libwebsockets context
 * @wsi:		Websocket instance (available from user callback)
 * @code:		Status index, eg, 404
 * @html_body:		User-readable HTML description, or NULL
 *
 *	Helper to report HTTP errors back to the client cleanly and
 *	consistently
 */
LWS_VISIBLE int libwebsockets_return_http_status(
		struct libwebsocket_context *context, struct libwebsocket *wsi,
				       unsigned int code, const char *html_body)
{
	int n, m;
	const char *description = "";

	if (!html_body)
		html_body = "";

	if (code >= 400 && code < (400 + ARRAY_SIZE(err400)))
		description = err400[code - 400];
	if (code >= 500 && code < (500 + ARRAY_SIZE(err500)))
		description = err500[code - 500];

	n = sprintf((char *)context->service_buffer,
		"HTTP/1.0 %u %s\x0d\x0a"
		"Server: libwebsockets\x0d\x0a"
		"Content-Type: text/html\x0d\x0a\x0d\x0a"
		"<h1>%u %s</h1>%s",
		code, description, code, description, html_body);

	lwsl_info((const char *)context->service_buffer);

	m = libwebsocket_write(wsi, context->service_buffer, n, LWS_WRITE_HTTP);

	return m;
}

/**
 * libwebsockets_serve_http_file() - Send a file back to the client using http
 * @context:		libwebsockets context
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 * @other_headers:	NULL or pointer to \0-terminated other header string
 *
 *	This function is intended to be called from the callback in response
 *	to http requests from the client.  It allows the callback to issue
 *	local files down the http link in a single step.
 *
 *	Returning <0 indicates error and the wsi should be closed.  Returning
 *	>0 indicates the file was completely sent and the wsi should be closed.
 *	==0 indicates the file transfer is started and needs more service later,
 *	the wsi should be left alone.
 */

LWS_VISIBLE int libwebsockets_serve_http_file(
		struct libwebsocket_context *context,
			struct libwebsocket *wsi, const char *file,
			   const char *content_type, const char *other_headers)
{
	unsigned char *p = context->service_buffer;
	int ret = 0;
	int n;

	wsi->u.http.fd = lws_plat_open_file(file, &wsi->u.http.filelen);

	if (wsi->u.http.fd == LWS_INVALID_FILE) {
		lwsl_err("Unable to open '%s'\n", file);
		libwebsockets_return_http_status(context, wsi,
						HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	p += sprintf((char *)p,
"HTTP/1.0 200 OK\x0d\x0aServer: libwebsockets\x0d\x0a""Content-Type: %s\x0d\x0a",
								  content_type);
	if (other_headers) {
		n = strlen(other_headers);
		memcpy(p, other_headers, n);
		p += n;
	}
	p += sprintf((char *)p,
		"Content-Length: %lu\x0d\x0a\x0d\x0a", wsi->u.http.filelen);

	ret = libwebsocket_write(wsi, context->service_buffer,
				   p - context->service_buffer, LWS_WRITE_HTTP);
	if (ret != (p - context->service_buffer)) {
		lwsl_err("_write returned %d from %d\n", ret, (p - context->service_buffer));
		return -1;
	}

	wsi->u.http.filepos = 0;
	wsi->state = WSI_STATE_HTTP_ISSUING_FILE;

	return libwebsockets_serve_http_file_fragment(context, wsi);
}


int libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	size_t n = 0;
	int m;

#if 0
	lwsl_parser("received %d byte packet\n", (int)len);
	lwsl_hexdump(buf, len);
#endif

	/* let the rx protocol state machine have as much as it needs */

	while (n < len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (!(wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			/* his RX is flowcontrolled, don't send remaining now */
			if (!wsi->u.ws.rxflow_buffer) {
				/* a new rxflow, buffer it and warn caller */
				lwsl_info("new rxflow input buffer len %d\n",
								       len - n);
				wsi->u.ws.rxflow_buffer =
					       (unsigned char *)malloc(len - n);
				wsi->u.ws.rxflow_len = len - n;
				wsi->u.ws.rxflow_pos = 0;
				memcpy(wsi->u.ws.rxflow_buffer,
							buf + n, len - n);
			} else
				/* rxflow while we were spilling prev rxflow */
				lwsl_info("stalling in existing rxflow buf\n");

			return 1;
		}

		/* account for what we're using in rxflow buffer */
		if (wsi->u.ws.rxflow_buffer)
			wsi->u.ws.rxflow_pos++;

		/* process the byte */
		m = libwebsocket_rx_sm(wsi, buf[n++]);
		if (m < 0)
			return -1;
	}

	return 0;
}

LWS_VISIBLE void
lws_server_get_canonical_hostname(struct libwebsocket_context *context,
				struct lws_context_creation_info *info)
{
	if (info->options & LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME)
		return;

	/* find canonical hostname */
	gethostname((char *)context->canonical_hostname,
				       sizeof(context->canonical_hostname) - 1);

	lwsl_notice(" canonical_hostname = %s\n", context->canonical_hostname);
}

/***************************************************
 * external/libwebsockets/src/server-handshake.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }
#ifndef LWS_NO_EXTENSIONS
LWS_VISIBLE int
lws_extension_server_handshake(struct libwebsocket_context *context,
			  struct libwebsocket *wsi, char **p)
{
	int n;
	char *c;
	char ext_name[128];
	struct libwebsocket_extension *ext;
	int ext_count = 0;
	int more = 1;

	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list
	 */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS))
		return 0;

	/*
	 * break down the list of client extensions
	 * and go through them
	 */

	if (lws_hdr_copy(wsi, (char *)context->service_buffer,
			sizeof(context->service_buffer),
					      WSI_TOKEN_EXTENSIONS) < 0)
		return 1;

	c = (char *)context->service_buffer;
	lwsl_parser("WSI_TOKEN_EXTENSIONS = '%s'\n", c);
	wsi->count_active_extensions = 0;
	n = 0;
	while (more) {

		if (*c && (*c != ',' && *c != ' ' && *c != '\t')) {
			ext_name[n] = *c++;
			if (n < sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		/* check a client's extension against our support */

		ext = wsi->protocol->owning_server->extensions;

		while (ext && ext->callback) {

			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			/*
			 * oh, we do support this one he
			 * asked for... but let's ask user
			 * code if it's OK to apply it on this
			 * particular connection + protocol
			 */

			n = wsi->protocol->owning_server->
				protocols[0].callback(
					wsi->protocol->owning_server,
					wsi,
				  LWS_CALLBACK_CONFIRM_EXTENSION_OKAY,
					  wsi->user_space, ext_name, 0);

			/*
			 * zero return from callback means
			 * go ahead and allow the extension,
			 * it's what we get if the callback is
			 * unhandled
			 */

			if (n) {
				ext++;
				continue;
			}

			/* apply it */

			if (ext_count)
				*(*p)++ = ',';
			else
				LWS_CPYAPP(*p,
				 "\x0d\x0aSec-WebSocket-Extensions: ");
			*p += sprintf(*p, "%s", ext_name);
			ext_count++;

			/* instantiate the extension on this conn */

			wsi->active_extensions_user[
				wsi->count_active_extensions] =
				     malloc(ext->per_session_data_size);
			if (wsi->active_extensions_user[
			     wsi->count_active_extensions] == NULL) {
				lwsl_err("Out of mem\n");
				return 1;
			}
			memset(wsi->active_extensions_user[
				wsi->count_active_extensions], 0,
					    ext->per_session_data_size);

			wsi->active_extensions[
				  wsi->count_active_extensions] = ext;

			/* allow him to construct his context */

			ext->callback(wsi->protocol->owning_server,
					ext, wsi,
					LWS_EXT_CALLBACK_CONSTRUCT,
					wsi->active_extensions_user[
				wsi->count_active_extensions], NULL, 0);

			wsi->count_active_extensions++;
			lwsl_parser("count_active_extensions <- %d\n",
					  wsi->count_active_extensions);

			ext++;
		}

		n = 0;
	}
	
	return 0;
}
#endif
int
handshake_0405(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	unsigned char hash[20];
	int n;
	char *response;
	char *p;
	int accept_len;

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST) ||
				!lws_hdr_total_length(wsi, WSI_TOKEN_KEY)) {
		lwsl_parser("handshake_04 missing pieces\n");
		/* completed header processing, but missing some bits */
		goto bail;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_KEY) >=
						     MAX_WEBSOCKET_04_KEY_LEN) {
		lwsl_warn("Client key too long %d\n", MAX_WEBSOCKET_04_KEY_LEN);
		goto bail;
	}

	/*
	 * since key length is restricted above (currently 128), cannot
	 * overflow
	 */
	n = sprintf((char *)context->service_buffer,
				"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
				lws_hdr_simple_ptr(wsi, WSI_TOKEN_KEY));

	SHA1(context->service_buffer, n, hash);

	accept_len = lws_b64_encode_string((char *)hash, 20,
			(char *)context->service_buffer,
			sizeof(context->service_buffer));
	if (accept_len < 0) {
		lwsl_warn("Base64 encoded hash too long\n");
		goto bail;
	}

	/* allocate the per-connection user memory (if any) */
	if (libwebsocket_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = (char *)context->service_buffer + MAX_WEBSOCKET_04_KEY_LEN;
	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Accept: ");
	strcpy(p, (char *)context->service_buffer);
	p += accept_len;

	if (lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL)) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		n = lws_hdr_copy(wsi, p, 128, WSI_TOKEN_PROTOCOL);
		if (n < 0)
			goto bail;
		p += n;
	}

#ifndef LWS_NO_EXTENSIONS
	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list
	 */
	if (lws_extension_server_handshake(context, wsi, &p))
		goto bail;
#endif
	/* end of response packet */

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");
	
	if (!lws_any_extension_handled(context, wsi,
			LWS_EXT_CALLBACK_HANDSHAKE_REPLY_TX,
						     response, p - response)) {

		/* okay send the handshake response accepting the connection */

		lwsl_parser("issuing resp pkt %d len\n", (int)(p - response));
#ifdef DEBUG
		fwrite(response, 1,  p - response, stderr);
#endif
		n = libwebsocket_write(wsi, (unsigned char *)response,
						  p - response, LWS_WRITE_HTTP);
		if (n != (p - response)) {
			lwsl_debug("handshake_0405: ERROR writing to socket\n");
			goto bail;
		}

	}

	/* alright clean up and set ourselves into established state */

	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;

	/* notify user code that we're ready to roll */

	if (wsi->protocol->callback)
		wsi->protocol->callback(wsi->protocol->owning_server,
				wsi, LWS_CALLBACK_ESTABLISHED,
					  wsi->user_space, NULL, 0);

	return 0;


bail:
	/* free up his parsing allocations */

	if (wsi->u.hdr.ah)
		free(wsi->u.hdr.ah);

	return -1;
}


/***************************************************
 * external/libwebsockets/src/service.cpp
 ***************************************************/

/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
		   struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd)
{
	int n;
	struct lws_tokens eff_buf;
	int ret;
	int m;
	int handled = 0;

	/* pending truncated sends have uber priority */

	if (wsi->truncated_send_len) {
		if (lws_issue_raw(wsi, wsi->truncated_send_malloc +
				wsi->truncated_send_offset,
						wsi->truncated_send_len) < 0) {
			lwsl_info("lws_handle_POLLOUT_event signalling to close\n");
			return -1;
		}
		/* leave POLLOUT active either way */
		return 0;
	} else
		if (wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			lwsl_info("***** %x signalling to close in POLLOUT handler\n", wsi);
			return -1; /* retry closing now */
		}


	m = lws_ext_callback_for_each_active(wsi, LWS_EXT_CALLBACK_IS_WRITEABLE,
								       NULL, 0);
	if (handled == 1)
		goto notify_action;
#ifndef LWS_NO_EXTENSIONS
	if (!wsi->extension_data_pending || handled == 2)
		goto user_service;
#endif
	/*
	 * check in on the active extensions, see if they
	 * had pending stuff to spill... they need to get the
	 * first look-in otherwise sequence will be disordered
	 *
	 * NULL, zero-length eff_buf means just spill pending
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* give every extension a chance to spill */
		
		m = lws_ext_callback_for_each_active(wsi,
					LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
							           &eff_buf, 0);
		if (m < 0) {
			lwsl_err("ext reports fatal error\n");
			return -1;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							     eff_buf.token_len);
			if (n < 0) {
				lwsl_info("closing from POLLOUT spill\n");
				return -1;
			}
			/*
			 * Keep amount spilled small to minimize chance of this
			 */
			if (n != eff_buf.token_len) {
				lwsl_err("Unable to spill ext %d vs %s\n",
							  eff_buf.token_len, n);
				return -1;
			}
		} else
			continue;

		/* no extension has more to spill */

		if (!ret)
			continue;

		/*
		 * There's more to spill from an extension, but we just sent
		 * something... did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		lwsl_info("choked in POLLOUT service\n");

		/*
		 * Yes, he's choked.  Leave the POLLOUT masked on so we will
		 * come back here when he is unchoked.  Don't call the user
		 * callback to enforce ordering of spilling, he'll get called
		 * when we come back here and there's nothing more to spill.
		 */

		return 0;
	}
#ifndef LWS_NO_EXTENSIONS
	wsi->extension_data_pending = 0;

user_service:
#endif
	/* one shot */

	if (pollfd) {
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			return 1;

		lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_WRITE);
	}

notify_action:
	if (wsi->mode == LWS_CONNMODE_WS_CLIENT)
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
	else
		n = LWS_CALLBACK_SERVER_WRITEABLE;

	return user_callback_handle_rxflow(wsi->protocol->callback, context,
			wsi, (enum libwebsocket_callback_reasons) n,
						      wsi->user_space, NULL, 0);
}



int
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				     struct libwebsocket *wsi, unsigned int sec)
{
	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */
	if (lws_ext_callback_for_each_active(wsi, LWS_EXT_CALLBACK_1HZ, NULL, sec) < 0)
		return 0;

	if (!wsi->pending_timeout)
		return 0;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */
	if (sec > wsi->pending_timeout_limit) {
		lwsl_info("TIMEDOUT WAITING on %d\n", wsi->pending_timeout);
		libwebsocket_close_and_free_session(context,
						wsi, LWS_CLOSE_STATUS_NOSTATUS);
		return 1;
	}

	return 0;
}

/**
 * libwebsocket_service_fd() - Service polled socket with something waiting
 * @context:	Websocket context
 * @pollfd:	The pollfd entry describing the socket fd and which events
 *		happened.
 *
 *	This function takes a pollfd that has POLLIN or POLLOUT activity and
 *	services it according to the state of the associated
 *	struct libwebsocket.
 *
 *	The one call deals with all "service" that might happen on a socket
 *	including listen accepts, http files as well as websocket protocol.
 *
 *	If a pollfd says it has something, you can just pass it to
 *	libwebsocket_serice_fd() whether it is a socket handled by lws or not.
 *	If it sees it is a lws socket, the traffic will be handled and
 *	pollfd->revents will be zeroed now.
 *
 *	If the socket is foreign to lws, it leaves revents alone.  So you can
 *	see if you should service yourself by checking the pollfd revents
 *	after letting lws try to service it.
 */

LWS_VISIBLE int
libwebsocket_service_fd(struct libwebsocket_context *context,
							  struct libwebsocket_pollfd *pollfd)
{
	struct libwebsocket *wsi;
	int n;
	int m;
	int listen_socket_fds_index = 0;
	time_t now;
	int timed_out = 0;
	int our_fd = 0;
	char draining_flow = 0;
	int more;
	struct lws_tokens eff_buf;

	if (context->listen_service_fd)
		listen_socket_fds_index = context->lws_lookup[
			     context->listen_service_fd]->position_in_fds_table;

	/*
	 * you can call us with pollfd = NULL to just allow the once-per-second
	 * global timeout checks; if less than a second since the last check
	 * it returns immediately then.
	 */

	time(&now);

	/* TODO: if using libev, we should probably use timeout watchers... */
	if (context->last_timeout_check_s != now) {
		context->last_timeout_check_s = now;

		lws_plat_service_periodic(context);

		/* global timeout check once per second */

		if (pollfd)
			our_fd = pollfd->fd;

		for (n = 0; n < context->fds_count; n++) {
			m = context->fds[n].fd;
			wsi = context->lws_lookup[m];
			if (!wsi)
				continue;

			if (libwebsocket_service_timeout_check(context, wsi, now))
				/* he did time out... */
				if (m == our_fd) {
					/* it was the guy we came to service! */
					timed_out = 1;
					/* mark as handled */
					pollfd->revents = 0;
				}
		}
	}

	/* the socket we came to service timed out, nothing to do */
	if (timed_out)
		return 0;

	/* just here for timeout management? */
	if (pollfd == NULL)
		return 0;

	/* no, here to service a socket descriptor */
	wsi = context->lws_lookup[pollfd->fd];
	if (wsi == NULL)
		/* not lws connection ... leave revents alone and return */
		return 0;

	/*
	 * so that caller can tell we handled, past here we need to
	 * zero down pollfd->revents after handling
	 */

	/*
	 * deal with listen service piggybacking
	 * every listen_service_modulo services of other fds, we
	 * sneak one in to service the listen socket if there's anything waiting
	 *
	 * To handle connection storms, as found in ab, if we previously saw a
	 * pending connection here, it causes us to check again next time.
	 */

	if (context->listen_service_fd && pollfd !=
				       &context->fds[listen_socket_fds_index]) {
		context->listen_service_count++;
		if (context->listen_service_extraseen ||
				context->listen_service_count ==
					       context->listen_service_modulo) {
			context->listen_service_count = 0;
			m = 1;
			if (context->listen_service_extraseen > 5)
				m = 2;
			while (m--) {
				/*
				 * even with extpoll, we prepared this
				 * internal fds for listen
				 */
				n = lws_poll_listen_fd(&context->fds[listen_socket_fds_index]);
				if (n > 0) { /* there's a conn waiting for us */
					libwebsocket_service_fd(context,
						&context->
						  fds[listen_socket_fds_index]);
					context->listen_service_extraseen++;
				} else {
					if (context->listen_service_extraseen)
						context->
						     listen_service_extraseen--;
					break;
				}
			}
		}

	}

	/* handle session socket closed */

	if ((!(pollfd->revents & LWS_POLLIN)) &&
			(pollfd->revents & LWS_POLLHUP)) {

		lwsl_debug("Session Socket %p (fd=%d) dead\n",
						       (void *)wsi, pollfd->fd);

		goto close_and_handled;
	}

	/* okay, what we came here to do... */

	switch (wsi->mode) {
	case LWS_CONNMODE_HTTP_SERVING:
	case LWS_CONNMODE_HTTP_SERVING_ACCEPTED:
	case LWS_CONNMODE_SERVER_LISTENER:
	case LWS_CONNMODE_SSL_ACK_PENDING:
		n = lws_server_socket_service(context, wsi, pollfd);
		if (n < 0)
			goto close_and_handled;
		goto handled;

	case LWS_CONNMODE_WS_SERVING:
	case LWS_CONNMODE_WS_CLIENT:

		/* the guy requested a callback when it was OK to write */

		if ((pollfd->revents & LWS_POLLOUT) &&
			(wsi->state == WSI_STATE_ESTABLISHED ||
				wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) &&
			   lws_handle_POLLOUT_event(context, wsi, pollfd)) {
			lwsl_info("libwebsocket_service_fd: closing\n");
			goto close_and_handled;
		}

		if (wsi->u.ws.rxflow_buffer &&
			      (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lwsl_info("draining rxflow\n");
			/* well, drain it */
			eff_buf.token = (char *)wsi->u.ws.rxflow_buffer +
						wsi->u.ws.rxflow_pos;
			eff_buf.token_len = wsi->u.ws.rxflow_len -
						wsi->u.ws.rxflow_pos;
			draining_flow = 1;
			goto drain;
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & LWS_POLLIN))
			break;

read_pending:
		eff_buf.token_len = lws_ssl_capable_read(wsi,
				context->service_buffer,
					       sizeof(context->service_buffer));
		switch (eff_buf.token_len) {
		case 0:
			lwsl_info("service_fd: closing due to 0 length read\n");
			goto close_and_handled;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			lwsl_info("SSL Capable more service\n");
			n = 0;
			goto handled;
		case LWS_SSL_CAPABLE_ERROR:
			lwsl_info("Closing when error\n");
			goto close_and_handled;
		}

		/*
		 * give any active extensions a chance to munge the buffer
		 * before parse.  We pass in a pointer to an lws_tokens struct
		 * prepared with the default buffer and content length that's in
		 * there.  Rather than rewrite the default buffer, extensions
		 * that expect to grow the buffer can adapt .token to
		 * point to their own per-connection buffer in the extension
		 * user allocation.  By default with no extensions or no
		 * extension callback handling, just the normal input buffer is
		 * used then so it is efficient.
		 */

		eff_buf.token = (char *)context->service_buffer;
drain:

		do {

			more = 0;
			
			m = lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_PACKET_RX_PREPARSE, &eff_buf, 0);
			if (m < 0)
				goto close_and_handled;
			if (m)
				more = 1;

			/* service incoming data */

			if (eff_buf.token_len) {
				n = libwebsocket_read(context, wsi,
					(unsigned char *)eff_buf.token,
							    eff_buf.token_len);
				if (n < 0) {
					/* we closed wsi */
					n = 0;
					goto handled;
				}
			}

			eff_buf.token = NULL;
			eff_buf.token_len = 0;
		} while (more);

		if (draining_flow && wsi->u.ws.rxflow_buffer &&
				 wsi->u.ws.rxflow_pos == wsi->u.ws.rxflow_len) {
			lwsl_info("flow buffer: drained\n");
			free(wsi->u.ws.rxflow_buffer);
			wsi->u.ws.rxflow_buffer = NULL;
			/* having drained the rxflow buffer, can rearm POLLIN */
			n = _libwebsocket_rx_flow_control(wsi); /* n ignored, needed for NO_SERVER case */
		}

		if (lws_ssl_pending(wsi))
			goto read_pending;
		break;

	default:
#ifdef LWS_NO_CLIENT
		break;
#else
		n = lws_client_socket_service(context, wsi, pollfd);
		goto handled;
#endif
	}

	n = 0;
	goto handled;

close_and_handled:
	lwsl_debug("Close and handled\n");
	libwebsocket_close_and_free_session(context, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
	n = 1;

handled:
	pollfd->revents = 0;
	return n;
}

/**
 * libwebsocket_service() - Service any pending websocket activity
 * @context:	Websocket context
 * @timeout_ms:	Timeout for poll; 0 means return immediately if nothing needed
 *		service otherwise block and service immediately, returning
 *		after the timeout if nothing needed service.
 *
 *	This function deals with any pending websocket traffic, for three
 *	kinds of event.  It handles these events on both server and client
 *	types of connection the same.
 *
 *	1) Accept new connections to our context's server
 *
 *	2) Call the receive callback for incoming frame data received by
 *	    server or client connections.
 *
 *	You need to call this service function periodically to all the above
 *	functions to happen; if your application is single-threaded you can
 *	just call it in your main event loop.
 *
 *	Alternatively you can fork a new process that asynchronously handles
 *	calling this service in a loop.  In that case you are happy if this
 *	call blocks your thread until it needs to take care of something and
 *	would call it with a large nonzero timeout.  Your loop then takes no
 *	CPU while there is nothing happening.
 *
 *	If you are calling it in a single-threaded app, you don't want it to
 *	wait around blocking other things in your loop from happening, so you
 *	would call it with a timeout_ms of 0, so it returns immediately if
 *	nothing is pending, or as soon as it services whatever was pending.
 */

LWS_VISIBLE int
libwebsocket_service(struct libwebsocket_context *context, int timeout_ms)
{
	return lws_plat_service(context, timeout_ms);
}


/***************************************************
 * external/libwebsockets/src/sha-1.cpp
 ***************************************************/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * FIPS pub 180-1: Secure Hash Algorithm (SHA-1)
 * based on: http://csrc.nist.gov/fips/fip180-1.txt
 * implemented by Jun-ichiro itojun Itoh <itojun@itojun.org>
 */

#ifndef WEBSOCKET_IS_AMALGAMATION
#include "private-libwebsockets.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

struct sha1_ctxt {
	union {
		unsigned char		b8[20];
		unsigned int		b32[5];
	} h;
	union {
		unsigned char		b8[8];
		u_int64_t		b64[1];
	} c;
	union {
		unsigned char		b8[64];
		unsigned int		b32[16];
	} m;
	unsigned char			count;
};

/* sanity check */
#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
# define unsupported 1
#elif BYTE_ORDER != BIG_ENDIAN
# if BYTE_ORDER != LITTLE_ENDIAN
#  define unsupported 1
# endif
#endif

#ifndef unsupported

/* constant table */
static const unsigned int _K[] =
			{ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
#define	K(t)	_K[(t) / 20]

#define	F0(b, c, d)	(((b) & (c)) | ((~(b)) & (d)))
#define	F1(b, c, d)	(((b) ^ (c)) ^ (d))
#define	F2(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define	F3(b, c, d)	(((b) ^ (c)) ^ (d))

#define	S(n, x)		(((x) << (n)) | ((x) >> (32 - n)))

#define	H(n)	(ctxt->h.b32[(n)])
#define	COUNT	(ctxt->count)
#define	BCOUNT	(ctxt->c.b64[0] / 8)
#define	W(n)	(ctxt->m.b32[(n)])

#define	PUTBYTE(x)	{ \
	ctxt->m.b8[(COUNT % 64)] = (x);		\
	COUNT++;				\
	COUNT %= 64;				\
	ctxt->c.b64[0] += 8;			\
	if (COUNT % 64 == 0)			\
		sha1_step(ctxt);		\
	}

#define	PUTPAD(x)	{ \
	ctxt->m.b8[(COUNT % 64)] = (x);		\
	COUNT++;				\
	COUNT %= 64;				\
	if (COUNT % 64 == 0)			\
		sha1_step(ctxt);		\
	}

static void sha1_step __P((struct sha1_ctxt *));

static void
sha1_step(struct sha1_ctxt *ctxt)
{
	unsigned int	a, b, c, d, e, tmp;
	size_t t, s;

#if BYTE_ORDER == LITTLE_ENDIAN
	struct sha1_ctxt tctxt;

	memcpy(&tctxt.m.b8[0], &ctxt->m.b8[0], 64);
	ctxt->m.b8[0] = tctxt.m.b8[3]; ctxt->m.b8[1] = tctxt.m.b8[2];
	ctxt->m.b8[2] = tctxt.m.b8[1]; ctxt->m.b8[3] = tctxt.m.b8[0];
	ctxt->m.b8[4] = tctxt.m.b8[7]; ctxt->m.b8[5] = tctxt.m.b8[6];
	ctxt->m.b8[6] = tctxt.m.b8[5]; ctxt->m.b8[7] = tctxt.m.b8[4];
	ctxt->m.b8[8] = tctxt.m.b8[11]; ctxt->m.b8[9] = tctxt.m.b8[10];
	ctxt->m.b8[10] = tctxt.m.b8[9]; ctxt->m.b8[11] = tctxt.m.b8[8];
	ctxt->m.b8[12] = tctxt.m.b8[15]; ctxt->m.b8[13] = tctxt.m.b8[14];
	ctxt->m.b8[14] = tctxt.m.b8[13]; ctxt->m.b8[15] = tctxt.m.b8[12];
	ctxt->m.b8[16] = tctxt.m.b8[19]; ctxt->m.b8[17] = tctxt.m.b8[18];
	ctxt->m.b8[18] = tctxt.m.b8[17]; ctxt->m.b8[19] = tctxt.m.b8[16];
	ctxt->m.b8[20] = tctxt.m.b8[23]; ctxt->m.b8[21] = tctxt.m.b8[22];
	ctxt->m.b8[22] = tctxt.m.b8[21]; ctxt->m.b8[23] = tctxt.m.b8[20];
	ctxt->m.b8[24] = tctxt.m.b8[27]; ctxt->m.b8[25] = tctxt.m.b8[26];
	ctxt->m.b8[26] = tctxt.m.b8[25]; ctxt->m.b8[27] = tctxt.m.b8[24];
	ctxt->m.b8[28] = tctxt.m.b8[31]; ctxt->m.b8[29] = tctxt.m.b8[30];
	ctxt->m.b8[30] = tctxt.m.b8[29]; ctxt->m.b8[31] = tctxt.m.b8[28];
	ctxt->m.b8[32] = tctxt.m.b8[35]; ctxt->m.b8[33] = tctxt.m.b8[34];
	ctxt->m.b8[34] = tctxt.m.b8[33]; ctxt->m.b8[35] = tctxt.m.b8[32];
	ctxt->m.b8[36] = tctxt.m.b8[39]; ctxt->m.b8[37] = tctxt.m.b8[38];
	ctxt->m.b8[38] = tctxt.m.b8[37]; ctxt->m.b8[39] = tctxt.m.b8[36];
	ctxt->m.b8[40] = tctxt.m.b8[43]; ctxt->m.b8[41] = tctxt.m.b8[42];
	ctxt->m.b8[42] = tctxt.m.b8[41]; ctxt->m.b8[43] = tctxt.m.b8[40];
	ctxt->m.b8[44] = tctxt.m.b8[47]; ctxt->m.b8[45] = tctxt.m.b8[46];
	ctxt->m.b8[46] = tctxt.m.b8[45]; ctxt->m.b8[47] = tctxt.m.b8[44];
	ctxt->m.b8[48] = tctxt.m.b8[51]; ctxt->m.b8[49] = tctxt.m.b8[50];
	ctxt->m.b8[50] = tctxt.m.b8[49]; ctxt->m.b8[51] = tctxt.m.b8[48];
	ctxt->m.b8[52] = tctxt.m.b8[55]; ctxt->m.b8[53] = tctxt.m.b8[54];
	ctxt->m.b8[54] = tctxt.m.b8[53]; ctxt->m.b8[55] = tctxt.m.b8[52];
	ctxt->m.b8[56] = tctxt.m.b8[59]; ctxt->m.b8[57] = tctxt.m.b8[58];
	ctxt->m.b8[58] = tctxt.m.b8[57]; ctxt->m.b8[59] = tctxt.m.b8[56];
	ctxt->m.b8[60] = tctxt.m.b8[63]; ctxt->m.b8[61] = tctxt.m.b8[62];
	ctxt->m.b8[62] = tctxt.m.b8[61]; ctxt->m.b8[63] = tctxt.m.b8[60];
#endif

	a = H(0); b = H(1); c = H(2); d = H(3); e = H(4);

	for (t = 0; t < 20; t++) {
		s = t & 0x0f;
		if (t >= 16)
			W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^
							W((s+2) & 0x0f) ^ W(s));

		tmp = S(5, a) + F0(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 20; t < 40; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^
							W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F1(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 40; t < 60; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^
							W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F2(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}
	for (t = 60; t < 80; t++) {
		s = t & 0x0f;
		W(s) = S(1, W((s+13) & 0x0f) ^ W((s+8) & 0x0f) ^
							W((s+2) & 0x0f) ^ W(s));
		tmp = S(5, a) + F3(b, c, d) + e + W(s) + K(t);
		e = d; d = c; c = S(30, b); b = a; a = tmp;
	}

	H(0) = H(0) + a;
	H(1) = H(1) + b;
	H(2) = H(2) + c;
	H(3) = H(3) + d;
	H(4) = H(4) + e;

	bzero(&ctxt->m.b8[0], 64);
}

/*------------------------------------------------------------*/

static void
sha1_init(struct sha1_ctxt *ctxt)
{
	bzero(ctxt, sizeof(struct sha1_ctxt));
	H(0) = 0x67452301;
	H(1) = 0xefcdab89;
	H(2) = 0x98badcfe;
	H(3) = 0x10325476;
	H(4) = 0xc3d2e1f0;
}

void
sha1_pad(struct sha1_ctxt *ctxt)
{
	size_t padlen;		/*pad length in bytes*/
	size_t padstart;

	PUTPAD(0x80);

	padstart = COUNT % 64;
	padlen = 64 - padstart;
	if (padlen < 8) {
		bzero(&ctxt->m.b8[padstart], padlen);
		COUNT += padlen;
		COUNT %= 64;
		sha1_step(ctxt);
		padstart = COUNT % 64;	/* should be 0 */
		padlen = 64 - padstart;	/* should be 64 */
	}
	bzero(&ctxt->m.b8[padstart], padlen - 8);
	COUNT += (padlen - 8);
	COUNT %= 64;
#if BYTE_ORDER == BIG_ENDIAN
	PUTPAD(ctxt->c.b8[0]); PUTPAD(ctxt->c.b8[1]);
	PUTPAD(ctxt->c.b8[2]); PUTPAD(ctxt->c.b8[3]);
	PUTPAD(ctxt->c.b8[4]); PUTPAD(ctxt->c.b8[5]);
	PUTPAD(ctxt->c.b8[6]); PUTPAD(ctxt->c.b8[7]);
#else
	PUTPAD(ctxt->c.b8[7]); PUTPAD(ctxt->c.b8[6]);
	PUTPAD(ctxt->c.b8[5]); PUTPAD(ctxt->c.b8[4]);
	PUTPAD(ctxt->c.b8[3]); PUTPAD(ctxt->c.b8[2]);
	PUTPAD(ctxt->c.b8[1]); PUTPAD(ctxt->c.b8[0]);
#endif
}

void
sha1_loop(struct sha1_ctxt *ctxt, const unsigned char *input, size_t len)
{
	size_t gaplen;
	size_t gapstart;
	size_t off;
	size_t copysiz;

	off = 0;

	while (off < len) {
		gapstart = COUNT % 64;
		gaplen = 64 - gapstart;

		copysiz = (gaplen < len - off) ? gaplen : len - off;
		memcpy(&ctxt->m.b8[gapstart], &input[off], copysiz);
		COUNT += copysiz;
		COUNT %= 64;
		ctxt->c.b64[0] += copysiz * 8;
		if (COUNT % 64 == 0)
			sha1_step(ctxt);
		off += copysiz;
	}
}

void
sha1_result(struct sha1_ctxt *ctxt, void *digest0)
{
	unsigned char *digest;

	digest = (unsigned char *)digest0;
	sha1_pad(ctxt);
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(digest, &ctxt->h.b8[0], 20);
#else
	digest[0] = ctxt->h.b8[3]; digest[1] = ctxt->h.b8[2];
	digest[2] = ctxt->h.b8[1]; digest[3] = ctxt->h.b8[0];
	digest[4] = ctxt->h.b8[7]; digest[5] = ctxt->h.b8[6];
	digest[6] = ctxt->h.b8[5]; digest[7] = ctxt->h.b8[4];
	digest[8] = ctxt->h.b8[11]; digest[9] = ctxt->h.b8[10];
	digest[10] = ctxt->h.b8[9]; digest[11] = ctxt->h.b8[8];
	digest[12] = ctxt->h.b8[15]; digest[13] = ctxt->h.b8[14];
	digest[14] = ctxt->h.b8[13]; digest[15] = ctxt->h.b8[12];
	digest[16] = ctxt->h.b8[19]; digest[17] = ctxt->h.b8[18];
	digest[18] = ctxt->h.b8[17]; digest[19] = ctxt->h.b8[16];
#endif
}

/*
 * This should look and work like the libcrypto implementation
 */

unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
	struct sha1_ctxt ctx;

	sha1_init(&ctx);
	sha1_loop(&ctx, d, n);
	sha1_result(&ctx, (void *)md);

	return md;
}

#endif /*unsupported*/
