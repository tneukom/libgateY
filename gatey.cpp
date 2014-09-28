/*
 * gatey amalgated source (http://jsoncpp.sourceforge.net/).
 */


/* libwebsockets code
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 * Distributed under lesser GPL with static linking exception
 */

/***************************************************
 * src/libwebsockets.h
 ***************************************************/

/*
 * libwebsockets amalgated header (http://jsoncpp.sourceforge.net/).
 */

#ifndef WEBSOCKET_AMALGATED_H_INCLUDED
#define WEBSOCKET_AMALGATED_H_INCLUDED
#define WEBSOCKET_IS_AMALGAMATION
/***************************************************
 * external/libwebsockets/src/libwebsockets.h
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

#ifndef LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C
#define LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#endif
	
#ifndef WEBSOCKET_IS_AMALGAMATION
#include "platforms.h"
#include "lws_config.h"
#endif

#if defined(WIN32) || defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <basetsd.h>

#define strcasecmp stricmp
#define getdtablesize() 30000

#define LWS_VISIBLE

#else // NOT WIN32

#include <poll.h>
#include <unistd.h>

#if defined(__GNUC__)
#define LWS_VISIBLE __attribute__((visibility("default")))
#else
#define LWS_VISIBLE
#endif

#endif

#ifdef LWS_USE_LIBEV
#include <ev.h>
#endif /* LWS_USE_LIBEV */

#include <assert.h>

#ifndef LWS_EXTERN
#define LWS_EXTERN extern
#endif
	
#ifdef _WIN32
#define random rand
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#define CONTEXT_PORT_NO_LISTEN -1
#define MAX_MUX_RECURSION 2

enum lws_log_levels {
	LLL_ERR = 1 << 0,
	LLL_WARN = 1 << 1,
	LLL_NOTICE = 1 << 2,
	LLL_INFO = 1 << 3,
	LLL_DEBUG = 1 << 4,
	LLL_PARSER = 1 << 5,
	LLL_HEADER = 1 << 6,
	LLL_EXT = 1 << 7,
	LLL_CLIENT = 1 << 8,
	LLL_LATENCY = 1 << 9,

	LLL_COUNT = 10 /* set to count of valid flags */
};

LWS_VISIBLE LWS_EXTERN void _lws_log(int filter, const char *format, ...);

/* notice, warn and log are always compiled in */
#define lwsl_notice(...) _lws_log(LLL_NOTICE, __VA_ARGS__)
#define lwsl_warn(...) _lws_log(LLL_WARN, __VA_ARGS__)
#define lwsl_err(...) _lws_log(LLL_ERR, __VA_ARGS__)
/*
 *  weaker logging can be deselected at configure time using --disable-debug
 *  that gets rid of the overhead of checking while keeping _warn and _err
 *  active
 */
#ifdef _DEBUG

#define lwsl_info(...) _lws_log(LLL_INFO, __VA_ARGS__)
#define lwsl_debug(...) _lws_log(LLL_DEBUG, __VA_ARGS__)
#define lwsl_parser(...) _lws_log(LLL_PARSER, __VA_ARGS__)
#define lwsl_header(...)  _lws_log(LLL_HEADER, __VA_ARGS__)
#define lwsl_ext(...)  _lws_log(LLL_EXT, __VA_ARGS__)
#define lwsl_client(...) _lws_log(LLL_CLIENT, __VA_ARGS__)
#define lwsl_latency(...) _lws_log(LLL_LATENCY, __VA_ARGS__)
LWS_VISIBLE LWS_EXTERN void lwsl_hexdump(void *buf, size_t len);

#else /* no debug */

#define lwsl_info(...)
#define lwsl_debug(...)
#define lwsl_parser(...)
#define lwsl_header(...)
#define lwsl_ext(...)
#define lwsl_client(...)
#define lwsl_latency(...)
#define lwsl_hexdump(a, b)

#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/* api change list for user code to test against */

#define LWS_FEATURE_SERVE_HTTP_FILE_HAS_OTHER_HEADERS_ARG


enum libwebsocket_context_options {
	LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT = 2,
	LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME = 4,
	LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT = 8,
	LWS_SERVER_OPTION_LIBEV = 16,
	LWS_SERVER_OPTION_DISABLE_IPV6 = 32,
	LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS = 64,
};

enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
	LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
	LWS_CALLBACK_CLIENT_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_CLOSED_HTTP,
	LWS_CALLBACK_RECEIVE,
	LWS_CALLBACK_CLIENT_RECEIVE,
	LWS_CALLBACK_CLIENT_RECEIVE_PONG,
	LWS_CALLBACK_CLIENT_WRITEABLE,
	LWS_CALLBACK_SERVER_WRITEABLE,
	LWS_CALLBACK_HTTP,
	LWS_CALLBACK_HTTP_BODY,
	LWS_CALLBACK_HTTP_BODY_COMPLETION,
	LWS_CALLBACK_HTTP_FILE_COMPLETION,
	LWS_CALLBACK_HTTP_WRITEABLE,
	LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
	LWS_CALLBACK_FILTER_HTTP_CONNECTION,
	LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED,
	LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
	LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
	LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
	LWS_CALLBACK_CONFIRM_EXTENSION_OKAY,
	LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED,
	LWS_CALLBACK_PROTOCOL_INIT,
	LWS_CALLBACK_PROTOCOL_DESTROY,
	LWS_CALLBACK_WSI_CREATE, /* always protocol[0] */
	LWS_CALLBACK_WSI_DESTROY, /* always protocol[0] */
	LWS_CALLBACK_GET_THREAD_ID,

	/* external poll() management support */
	LWS_CALLBACK_ADD_POLL_FD,
	LWS_CALLBACK_DEL_POLL_FD,
	LWS_CALLBACK_CHANGE_MODE_POLL_FD,
	LWS_CALLBACK_LOCK_POLL,
	LWS_CALLBACK_UNLOCK_POLL,

	LWS_CALLBACK_USER = 1000, /* user code can use any including / above */
};

// argument structure for all external poll related calls
// passed in via 'in'
struct libwebsocket_pollargs {
    int fd;            // applicable file descriptor
    int events;        // the new event mask
    int prev_events;   // the previous event mask
};

#ifdef _WIN32
struct libwebsocket_pollfd {
	SOCKET fd;
	SHORT events;
	SHORT revents;
};
#else
#define libwebsocket_pollfd pollfd
#endif

enum libwebsocket_extension_callback_reasons {
	LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT,
	LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT,
	LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT,
	LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT,
	LWS_EXT_CALLBACK_CONSTRUCT,
	LWS_EXT_CALLBACK_CLIENT_CONSTRUCT,
	LWS_EXT_CALLBACK_CHECK_OK_TO_REALLY_CLOSE,
	LWS_EXT_CALLBACK_CHECK_OK_TO_PROPOSE_EXTENSION,
	LWS_EXT_CALLBACK_DESTROY,
	LWS_EXT_CALLBACK_DESTROY_ANY_WSI_CLOSING,
	LWS_EXT_CALLBACK_ANY_WSI_ESTABLISHED,
	LWS_EXT_CALLBACK_PACKET_RX_PREPARSE,
	LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
	LWS_EXT_CALLBACK_PACKET_TX_DO_SEND,
	LWS_EXT_CALLBACK_HANDSHAKE_REPLY_TX,
	LWS_EXT_CALLBACK_FLUSH_PENDING_TX,
	LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX,
	LWS_EXT_CALLBACK_CAN_PROXY_CLIENT_CONNECTION,
	LWS_EXT_CALLBACK_1HZ,
	LWS_EXT_CALLBACK_REQUEST_ON_WRITEABLE,
	LWS_EXT_CALLBACK_IS_WRITEABLE,
	LWS_EXT_CALLBACK_PAYLOAD_TX,
	LWS_EXT_CALLBACK_PAYLOAD_RX,
};

enum libwebsocket_write_protocol {
	LWS_WRITE_TEXT,
	LWS_WRITE_BINARY,
	LWS_WRITE_CONTINUATION,
	LWS_WRITE_HTTP,

	/* special 04+ opcodes */

	LWS_WRITE_CLOSE,
	LWS_WRITE_PING,
	LWS_WRITE_PONG,

	/* flags */

	LWS_WRITE_NO_FIN = 0x40,
	/*
	 * client packet payload goes out on wire unmunged
	 * only useful for security tests since normal servers cannot
	 * decode the content if used
	 */
	LWS_WRITE_CLIENT_IGNORE_XOR_MASK = 0x80
};

/*
 * you need these to look at headers that have been parsed if using the
 * LWS_CALLBACK_FILTER_CONNECTION callback.  If a header from the enum
 * list below is absent, .token = NULL and token_len = 0.  Otherwise .token
 * points to .token_len chars containing that header content.
 */

struct lws_tokens {
	char *token;
	int token_len;
};

enum lws_token_indexes {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_POST_URI,
	WSI_TOKEN_OPTIONS_URI,
	WSI_TOKEN_HOST,
	WSI_TOKEN_CONNECTION,
	WSI_TOKEN_KEY1,
	WSI_TOKEN_KEY2,
	WSI_TOKEN_PROTOCOL,
	WSI_TOKEN_UPGRADE,
	WSI_TOKEN_ORIGIN,
	WSI_TOKEN_DRAFT,
	WSI_TOKEN_CHALLENGE,

	/* new for 04 */
	WSI_TOKEN_KEY,
	WSI_TOKEN_VERSION,
	WSI_TOKEN_SWORIGIN,

	/* new for 05 */
	WSI_TOKEN_EXTENSIONS,

	/* client receives these */
	WSI_TOKEN_ACCEPT,
	WSI_TOKEN_NONCE,
	WSI_TOKEN_HTTP,

	/* http-related */
	WSI_TOKEN_HTTP_ACCEPT,
	WSI_TOKEN_HTTP_AC_REQUEST_HEADERS,
	WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
	WSI_TOKEN_HTTP_IF_NONE_MATCH,
	WSI_TOKEN_HTTP_ACCEPT_ENCODING,
	WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
	WSI_TOKEN_HTTP_PRAGMA,
	WSI_TOKEN_HTTP_CACHE_CONTROL,
	WSI_TOKEN_HTTP_AUTHORIZATION,
	WSI_TOKEN_HTTP_COOKIE,
	WSI_TOKEN_HTTP_CONTENT_LENGTH,
	WSI_TOKEN_HTTP_CONTENT_TYPE,
	WSI_TOKEN_HTTP_DATE,
	WSI_TOKEN_HTTP_RANGE,
	WSI_TOKEN_HTTP_REFERER,
	WSI_TOKEN_HTTP_URI_ARGS,


	WSI_TOKEN_MUXURL,

	/* use token storage to stash these */

	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_PEER_ADDRESS,
	_WSI_TOKEN_CLIENT_URI,
	_WSI_TOKEN_CLIENT_HOST,
	_WSI_TOKEN_CLIENT_ORIGIN,

	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE,
	WSI_INIT_TOKEN_MUXURL,
};

struct lws_token_limits {
    unsigned short token_limit[WSI_TOKEN_COUNT];
};

/*
 * From RFC 6455
   1000

      1000 indicates a normal closure, meaning that the purpose for
      which the connection was established has been fulfilled.

   1001

      1001 indicates that an endpoint is "going away", such as a server
      going down or a browser having navigated away from a page.

   1002

      1002 indicates that an endpoint is terminating the connection due
      to a protocol error.

   1003

      1003 indicates that an endpoint is terminating the connection
      because it has received a type of data it cannot accept (e.g., an
      endpoint that understands only text data MAY send this if it
      receives a binary message).

   1004

      Reserved.  The specific meaning might be defined in the future.

   1005

      1005 is a reserved value and MUST NOT be set as a status code in a
      Close control frame by an endpoint.  It is designated for use in
      applications expecting a status code to indicate that no status
      code was actually present.

   1006

      1006 is a reserved value and MUST NOT be set as a status code in a
      Close control frame by an endpoint.  It is designated for use in
      applications expecting a status code to indicate that the
      connection was closed abnormally, e.g., without sending or
      receiving a Close control frame.

   1007

      1007 indicates that an endpoint is terminating the connection
      because it has received data within a message that was not
      consistent with the type of the message (e.g., non-UTF-8 [RFC3629]
      data within a text message).

   1008

      1008 indicates that an endpoint is terminating the connection
      because it has received a message that violates its policy.  This
      is a generic status code that can be returned when there is no
      other more suitable status code (e.g., 1003 or 1009) or if there
      is a need to hide specific details about the policy.

   1009

      1009 indicates that an endpoint is terminating the connection
      because it has received a message that is too big for it to
      process.

   1010

      1010 indicates that an endpoint (client) is terminating the
      connection because it has expected the server to negotiate one or
      more extension, but the server didn't return them in the response
      message of the WebSocket handshake.  The list of extensions that
      are needed SHOULD appear in the /reason/ part of the Close frame.
      Note that this status code is not used by the server, because it
      can fail the WebSocket handshake instead.

   1011

      1011 indicates that a server is terminating the connection because
      it encountered an unexpected condition that prevented it from
      fulfilling the request.

   1015

      1015 is a reserved value and MUST NOT be set as a status code in a
      Close control frame by an endpoint.  It is designated for use in
      applications expecting a status code to indicate that the
      connection was closed due to a failure to perform a TLS handshake
      (e.g., the server certificate can't be verified).
*/

enum lws_close_status {
	LWS_CLOSE_STATUS_NOSTATUS = 0,
	LWS_CLOSE_STATUS_NORMAL = 1000,
	LWS_CLOSE_STATUS_GOINGAWAY = 1001,
	LWS_CLOSE_STATUS_PROTOCOL_ERR = 1002,
	LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE = 1003,
	LWS_CLOSE_STATUS_RESERVED = 1004,
	LWS_CLOSE_STATUS_NO_STATUS = 1005,
	LWS_CLOSE_STATUS_ABNORMAL_CLOSE = 1006,
	LWS_CLOSE_STATUS_INVALID_PAYLOAD = 1007,
	LWS_CLOSE_STATUS_POLICY_VIOLATION = 1008,
	LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE = 1009,
	LWS_CLOSE_STATUS_EXTENSION_REQUIRED = 1010,
	LWS_CLOSE_STATUS_UNEXPECTED_CONDITION = 1011,
	LWS_CLOSE_STATUS_TLS_FAILURE = 1015,
};

enum http_status {
	HTTP_STATUS_OK = 200,
	HTTP_STATUS_NO_CONTENT = 204,

	HTTP_STATUS_BAD_REQUEST = 400,
	HTTP_STATUS_UNAUTHORIZED,
	HTTP_STATUS_PAYMENT_REQUIRED,
	HTTP_STATUS_FORBIDDEN,
	HTTP_STATUS_NOT_FOUND,
	HTTP_STATUS_METHOD_NOT_ALLOWED,
	HTTP_STATUS_NOT_ACCEPTABLE,
	HTTP_STATUS_PROXY_AUTH_REQUIRED,
	HTTP_STATUS_REQUEST_TIMEOUT,
	HTTP_STATUS_CONFLICT,
	HTTP_STATUS_GONE,
	HTTP_STATUS_LENGTH_REQUIRED,
	HTTP_STATUS_PRECONDITION_FAILED,
	HTTP_STATUS_REQ_ENTITY_TOO_LARGE,
	HTTP_STATUS_REQ_URI_TOO_LONG,
	HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
	HTTP_STATUS_REQ_RANGE_NOT_SATISFIABLE,
	HTTP_STATUS_EXPECTATION_FAILED,

	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
	HTTP_STATUS_NOT_IMPLEMENTED,
	HTTP_STATUS_BAD_GATEWAY,
	HTTP_STATUS_SERVICE_UNAVAILABLE,
	HTTP_STATUS_GATEWAY_TIMEOUT,
	HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
};

struct libwebsocket;
struct libwebsocket_context;
/* needed even with extensions disabled for create context */
struct libwebsocket_extension;

/**
 * callback_function() - User server actions
 * @context:	Websockets context
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @user:	Pointer to per-session user data allocated by library
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 *
 *	This callback is the way the user controls what is served.  All the
 *	protocol detail is hidden and handled by the library.
 *
 *	For each connection / session there is user data allocated that is
 *	pointed to by "user".  You set the size of this user data area when
 *	the library is initialized with libwebsocket_create_server.
 *
 *	You get an opportunity to initialize user data when called back with
 *	LWS_CALLBACK_ESTABLISHED reason.
 *
 *  LWS_CALLBACK_ESTABLISHED:  after the server completes a handshake with
 *				an incoming client
 *
 *  LWS_CALLBACK_CLIENT_CONNECTION_ERROR: the request client connection has
 *        been unable to complete a handshake with the remote server
 *
 *  LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH: this is the last chance for the
 *				client user code to examine the http headers
 *				and decide to reject the connection.  If the
 *				content in the headers is interesting to the
 *				client (url, etc) it needs to copy it out at
 *				this point since it will be destroyed before
 *				the CLIENT_ESTABLISHED call
 *
 *  LWS_CALLBACK_CLIENT_ESTABLISHED: after your client connection completed
 *				a handshake with the remote server
 *
 *	LWS_CALLBACK_CLOSED: when the websocket session ends
 *
 *	LWS_CALLBACK_CLOSED_HTTP: when a HTTP (non-websocket) session ends
 *
 *	LWS_CALLBACK_RECEIVE: data has appeared for this server endpoint from a
 *				remote client, it can be found at *in and is
 *				len bytes long
 *
 *	LWS_CALLBACK_CLIENT_RECEIVE_PONG: if you elected to see PONG packets,
 *				they appear with this callback reason.  PONG
 *				packets only exist in 04+ protocol
 *
 *	LWS_CALLBACK_CLIENT_RECEIVE: data has appeared from the server for the
 *				client connection, it can be found at *in and
 *				is len bytes long
 *
 *	LWS_CALLBACK_HTTP: an http request has come from a client that is not
 *				asking to upgrade the connection to a websocket
 *				one.  This is a chance to serve http content,
 *				for example, to send a script to the client
 *				which will then open the websockets connection.
 *				@in points to the URI path requested and
 *				libwebsockets_serve_http_file() makes it very
 *				simple to send back a file to the client.
 *				Normally after sending the file you are done
 *				with the http connection, since the rest of the
 *				activity will come by websockets from the script
 *				that was delivered by http, so you will want to
 *				return 1; to close and free up the connection.
 *				That's important because it uses a slot in the
 *				total number of client connections allowed set
 *				by MAX_CLIENTS.
 *
 *	LWS_CALLBACK_HTTP_BODY: the next @len bytes data from the http
 *		request body HTTP connection is now available in @in.
 *
 *	LWS_CALLBACK_HTTP_BODY_COMPLETION: the expected amount of http request
 *		body has been delivered
 *
 *	LWS_CALLBACK_HTTP_WRITEABLE: you can write more down the http protocol
 *		link now.
 *
 *	LWS_CALLBACK_HTTP_FILE_COMPLETION: a file requested to be send down
 *				http link has completed.
 *
 *	LWS_CALLBACK_CLIENT_WRITEABLE:
 *      LWS_CALLBACK_SERVER_WRITEABLE:   If you call
 *		libwebsocket_callback_on_writable() on a connection, you will
 *		get one of these callbacks coming when the connection socket
 *		is able to accept another write packet without blocking.
 *		If it already was able to take another packet without blocking,
 *		you'll get this callback at the next call to the service loop
 *		function.  Notice that CLIENTs get LWS_CALLBACK_CLIENT_WRITEABLE
 *		and servers get LWS_CALLBACK_SERVER_WRITEABLE.
 *
 *	LWS_CALLBACK_FILTER_NETWORK_CONNECTION: called when a client connects to
 *		the server at network level; the connection is accepted but then
 *		passed to this callback to decide whether to hang up immediately
 *		or not, based on the client IP.  @in contains the connection
 *		socket's descriptor. Since the client connection information is
 *		not available yet, @wsi still pointing to the main server socket.
 *		Return non-zero to terminate the connection before sending or
 *		receiving anything. Because this happens immediately after the
 *		network connection from the client, there's no websocket protocol
 *		selected yet so this callback is issued only to protocol 0.
 * 
 *	LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED: A new client just had
 *		been connected, accepted, and instantiated into the pool. This
 *		callback allows setting any relevant property to it. Because this
 *		happens immediately after the instantiation of a new client,
 *		there's no websocket protocol selected yet so this callback is
 *		issued only to protocol 0. Only @wsi is defined, pointing to the
 *		new client, and the return value is ignored.
 *
 *	LWS_CALLBACK_FILTER_HTTP_CONNECTION: called when the request has
 *		been received and parsed from the client, but the response is
 *		not sent yet.  Return non-zero to disallow the connection.
 *		@user is a pointer to the connection user space allocation,
 *		@in is the URI, eg, "/"
 *		In your handler you can use the public APIs
 *		lws_hdr_total_length() / lws_hdr_copy() to access all of the
 *		headers using the header enums lws_token_indexes from
 *		libwebsockets.h to check for and read the supported header
 *		presence and content before deciding to allow the http
 *		connection to proceed or to kill the connection.
 *
 *	LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: called when the handshake has
 *		been received and parsed from the client, but the response is
 *		not sent yet.  Return non-zero to disallow the connection.
 *		@user is a pointer to the connection user space allocation,
 *		@in is the requested protocol name
 *		In your handler you can use the public APIs
 *		lws_hdr_total_length() / lws_hdr_copy() to access all of the
 *		headers using the header enums lws_token_indexes from
 *		libwebsockets.h to check for and read the supported header
 *		presence and content before deciding to allow the handshake
 *		to proceed or to kill the connection.
 *
 *	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: if configured for
 *		including OpenSSL support, this callback allows your user code
 *		to perform extra SSL_CTX_load_verify_locations() or similar
 *		calls to direct OpenSSL where to find certificates the client
 *		can use to confirm the remote server identity.  @user is the
 *		OpenSSL SSL_CTX*
 *
 *	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: if configured for
 *		including OpenSSL support, this callback allows your user code
 *		to load extra certifcates into the server which allow it to
 *		verify the validity of certificates returned by clients.  @user
 *		is the server's OpenSSL SSL_CTX*
 *
 *	LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: if the
 *		libwebsockets context was created with the option
 *		LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT, then this
 *		callback is generated during OpenSSL verification of the cert
 *		sent from the client.  It is sent to protocol[0] callback as
 *		no protocol has been negotiated on the connection yet.
 *		Notice that the libwebsockets context and wsi are both NULL
 *		during this callback.  See
 *		 http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
 *		to understand more detail about the OpenSSL callback that
 *		generates this libwebsockets callback and the meanings of the
 *		arguments passed.  In this callback, @user is the x509_ctx,
 *		@in is the ssl pointer and @len is preverify_ok
 *		Notice that this callback maintains libwebsocket return
 *		conventions, return 0 to mean the cert is OK or 1 to fail it.
 *		This also means that if you don't handle this callback then
 *		the default callback action of returning 0 allows the client
 *		certificates.
 *
 *	LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: this callback happens
 *		when a client handshake is being compiled.  @user is NULL,
 *		@in is a char **, it's pointing to a char * which holds the
 *		next location in the header buffer where you can add
 *		headers, and @len is the remaining space in the header buffer,
 *		which is typically some hundreds of bytes.  So, to add a canned
 *		cookie, your handler code might look similar to:
 *
 *		char **p = (char **)in;
 *
 *		if (len < 100)
 *			return 1;
 *
 *		*p += sprintf(*p, "Cookie: a=b\x0d\x0a");
 *
 *		return 0;
 *
 *		Notice if you add anything, you just have to take care about
 *		the CRLF on the line you added.  Obviously this callback is
 *		optional, if you don't handle it everything is fine.
 *
 *		Notice the callback is coming to protocols[0] all the time,
 *		because there is no specific protocol handshook yet.
 *
 *	LWS_CALLBACK_CONFIRM_EXTENSION_OKAY: When the server handshake code
 *		sees that it does support a requested extension, before
 *		accepting the extension by additing to the list sent back to
 *		the client it gives this callback just to check that it's okay
 *		to use that extension.  It calls back to the requested protocol
 *		and with @in being the extension name, @len is 0 and @user is
 *		valid.  Note though at this time the ESTABLISHED callback hasn't
 *		happened yet so if you initialize @user content there, @user
 *		content during this callback might not be useful for anything.
 *		Notice this callback comes to protocols[0].
 *
 *	LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:	When a client
 *		connection is being prepared to start a handshake to a server,
 *		each supported extension is checked with protocols[0] callback
 *		with this reason, giving the user code a chance to suppress the
 *		claim to support that extension by returning non-zero.  If
 *		unhandled, by default 0 will be returned and the extension
 *		support included in the header to the server.  Notice this
 *		callback comes to protocols[0].
 *
 *	LWS_CALLBACK_PROTOCOL_INIT:	One-time call per protocol so it can
 *		do initial setup / allocations etc
 *
 *	LWS_CALLBACK_PROTOCOL_DESTROY:	One-time call per protocol indicating
 *		this protocol won't get used at all after this callback, the
 *		context is getting destroyed.  Take the opportunity to
 *		deallocate everything that was allocated by the protocol.
 *
 *	LWS_CALLBACK_WSI_CREATE: outermost (earliest) wsi create notification
 *
 *	LWS_CALLBACK_WSI_DESTROY: outermost (latest) wsi destroy notification
 *
 *	The next five reasons are optional and only need taking care of if you
 *	will be integrating libwebsockets sockets into an external polling
 *	array.
 *
 *	For these calls, @in points to a struct libwebsocket_pollargs that
 *	contains @fd, @events and @prev_events members
 *
 *	LWS_CALLBACK_ADD_POLL_FD: libwebsocket deals with its poll() loop
 *		internally, but in the case you are integrating with another
 *		server you will need to have libwebsocket sockets share a
 *		polling array with the other server.  This and the other
 *		POLL_FD related callbacks let you put your specialized
 *		poll array interface code in the callback for protocol 0, the
 *		first protocol you support, usually the HTTP protocol in the
 *		serving case.
 *		This callback happens when a socket needs to be
 *		added to the polling loop: @in points to a struct
 *		libwebsocket_pollargs; the @fd member of the struct is the file
 *		descriptor, and @events contains the active events.
 *
 *		If you are using the internal polling loop (the "service"
 *		callback), you can just ignore these callbacks.
 *
 *	LWS_CALLBACK_DEL_POLL_FD: This callback happens when a socket descriptor
 *		needs to be removed from an external polling array.  @in is
 *		again the struct libwebsocket_pollargs containing the @fd member
 *		to be removed.  If you are using the internal polling
 *		loop, you can just ignore it.
 *
 *	LWS_CALLBACK_CHANGE_MODE_POLL_FD: This callback happens when
 *		libwebsockets wants to modify the events for a connectiion.
 *		@in is the struct libwebsocket_pollargs with the @fd to change.
 *		The new event mask is in @events member and the old mask is in
 *		the @prev_events member.
 *		If you are using the internal polling loop, you can just ignore
 *		it.
 *
 *	LWS_CALLBACK_LOCK_POLL:
 *	LWS_CALLBACK_UNLOCK_POLL: These allow the external poll changes driven
 *		by libwebsockets to participate in an external thread locking
 *		scheme around the changes, so the whole thing is threadsafe.
 */
LWS_VISIBLE LWS_EXTERN int callback(struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);

typedef int (callback_function)(struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);

#ifndef LWS_NO_EXTENSIONS
/**
 * extension_callback_function() - Hooks to allow extensions to operate
 * @context:	Websockets context
 * @ext:	This extension
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @user:	Pointer to per-session user data allocated by library
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 *
 *	Each extension that is active on a particular connection receives
 *	callbacks during the connection lifetime to allow the extension to
 *	operate on websocket data and manage itself.
 *
 *	Libwebsockets takes care of allocating and freeing "user" memory for
 *	each active extension on each connection.  That is what is pointed to
 *	by the @user parameter.
 *
 *	LWS_EXT_CALLBACK_CONSTRUCT:  called when the server has decided to
 *		select this extension from the list provided by the client,
 *		just before the server will send back the handshake accepting
 *		the connection with this extension active.  This gives the
 *		extension a chance to initialize its connection context found
 *		in @user.
 *
 *	LWS_EXT_CALLBACK_CLIENT_CONSTRUCT: same as LWS_EXT_CALLBACK_CONSTRUCT
 *		but called when client is instantiating this extension.  Some
 *		extensions will work the same on client and server side and then
 *		you can just merge handlers for both CONSTRUCTS.
 *
 *	LWS_EXT_CALLBACK_DESTROY:  called when the connection the extension was
 *		being used on is about to be closed and deallocated.  It's the
 *		last chance for the extension to deallocate anything it has
 *		allocated in the user data (pointed to by @user) before the
 *		user data is deleted.  This same callback is used whether you
 *		are in client or server instantiation context.
 *
 *	LWS_EXT_CALLBACK_PACKET_RX_PREPARSE: when this extension was active on
 *		a connection, and a packet of data arrived at the connection,
 *		it is passed to this callback to give the extension a chance to
 *		change the data, eg, decompress it.  @user is pointing to the
 *		extension's private connection context data, @in is pointing
 *		to an lws_tokens struct, it consists of a char * pointer called
 *		token, and an int called token_len.  At entry, these are
 *		set to point to the received buffer and set to the content
 *		length.  If the extension will grow the content, it should use
 *		a new buffer allocated in its private user context data and
 *		set the pointed-to lws_tokens members to point to its buffer.
 *
 *	LWS_EXT_CALLBACK_PACKET_TX_PRESEND: this works the same way as
 *		LWS_EXT_CALLBACK_PACKET_RX_PREPARSE above, except it gives the
 *		extension a chance to change websocket data just before it will
 *		be sent out.  Using the same lws_token pointer scheme in @in,
 *		the extension can change the buffer and the length to be
 *		transmitted how it likes.  Again if it wants to grow the
 *		buffer safely, it should copy the data into its own buffer and
 *		set the lws_tokens token pointer to it.
 */
LWS_VISIBLE LWS_EXTERN int extension_callback(struct libwebsocket_context *context,
			struct libwebsocket_extension *ext,
			struct libwebsocket *wsi,
			enum libwebsocket_extension_callback_reasons reason,
			void *user, void *in, size_t len);

typedef int (extension_callback_function)(struct libwebsocket_context *context,
			struct libwebsocket_extension *ext,
			struct libwebsocket *wsi,
			enum libwebsocket_extension_callback_reasons reason,
			void *user, void *in, size_t len);
#endif

/**
 * struct libwebsocket_protocols -	List of protocols and handlers server
 *					supports.
 * @name:	Protocol name that must match the one given in the client
 *		Javascript new WebSocket(url, 'protocol') name
 * @callback:	The service callback used for this protocol.  It allows the
 *		service action for an entire protocol to be encapsulated in
 *		the protocol-specific callback
 * @per_session_data_size:	Each new connection using this protocol gets
 *		this much memory allocated on connection establishment and
 *		freed on connection takedown.  A pointer to this per-connection
 *		allocation is passed into the callback in the 'user' parameter
 * @rx_buffer_size: if you want atomic frames delivered to the callback, you
 *		should set this to the size of the biggest legal frame that
 *		you support.  If the frame size is exceeded, there is no
 *		error, but the buffer will spill to the user callback when
 *		full, which you can detect by using
 *		libwebsockets_remaining_packet_payload().  Notice that you
 *		just talk about frame size here, the LWS_SEND_BUFFER_PRE_PADDING
 *		and post-padding are automatically also allocated on top.
 * @no_buffer_all_partial_tx:  Leave at zero if you want the library to take
 *		care of all partial tx for you.  It's useful if you only have
 *		small tx packets and the chance of any truncated send is small
 *		enough any additional malloc / buffering overhead is less
 *		painful than writing the code to deal with partial sends.  For
 *		protocols where you stream big blocks, set to nonzero and use
 *		the return value from libwebsocket_write() to manage how much
 *		got send yourself.
 * @owning_server:	the server init call fills in this opaque pointer when
 *		registering this protocol with the server.
 * @protocol_index: which protocol we are starting from zero
 *
 *	This structure represents one protocol supported by the server.  An
 *	array of these structures is passed to libwebsocket_create_server()
 *	allows as many protocols as you like to be handled by one server.
 */

struct libwebsocket_protocols {
	const char *name;
	callback_function *callback;
	size_t per_session_data_size;
	size_t rx_buffer_size;
	int no_buffer_all_partial_tx;

	/*
	 * below are filled in on server init and can be left uninitialized,
	 * no need for user to use them directly either
	 */

	struct libwebsocket_context *owning_server;
	int protocol_index;
};

#ifndef LWS_NO_EXTENSIONS
/**
 * struct libwebsocket_extension -	An extension we know how to cope with
 *
 * @name:			Formal extension name, eg, "deflate-stream"
 * @callback:			Service callback
 * @per_session_data_size:	Libwebsockets will auto-malloc this much
 *				memory for the use of the extension, a pointer
 *				to it comes in the @user callback parameter
 * @per_context_private_data:   Optional storage for this extension that
 *				is per-context, so it can track stuff across
 *				all sessions, etc, if it wants
 */

struct libwebsocket_extension {
	const char *name;
	extension_callback_function *callback;
	size_t per_session_data_size;
	void *per_context_private_data;
};
#endif

/**
 * struct lws_context_creation_info: parameters to create context with
 *
 * @port:	Port to listen on... you can use 0 to suppress listening on
 *		any port, that's what you want if you are not running a
 *		websocket server at all but just using it as a client
 * @iface:	NULL to bind the listen socket to all interfaces, or the
 *		interface name, eg, "eth2"
 * @protocols:	Array of structures listing supported protocols and a protocol-
 *		specific callback for each one.  The list is ended with an
 *		entry that has a NULL callback pointer.
 *		It's not const because we write the owning_server member
 * @extensions: NULL or array of libwebsocket_extension structs listing the
 *		extensions this context supports.  If you configured with
 *		--without-extensions, you should give NULL here.
 * @token_limits: NULL or struct lws_token_limits pointer which is initialized
 *      with a token length limit for each possible WSI_TOKEN_*** 
 * @ssl_cert_filepath:	If libwebsockets was compiled to use ssl, and you want
 *			to listen using SSL, set to the filepath to fetch the
 *			server cert from, otherwise NULL for unencrypted
 * @ssl_private_key_filepath: filepath to private key if wanting SSL mode,
 *			else ignored
 * @ssl_ca_filepath: CA certificate filepath or NULL
 * @ssl_cipher_list:	List of valid ciphers to use (eg,
 * 			"RC4-MD5:RC4-SHA:AES128-SHA:AES256-SHA:HIGH:!DSS:!aNULL"
 * 			or you can leave it as NULL to get "DEFAULT"
 * @gid:	group id to change to after setting listen socket, or -1.
 * @uid:	user id to change to after setting listen socket, or -1.
 * @options:	0, or LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK
 * @user:	optional user pointer that can be recovered via the context
 *		pointer using libwebsocket_context_user
 * @ka_time:	0 for no keepalive, otherwise apply this keepalive timeout to
 *		all libwebsocket sockets, client or server
 * @ka_probes:	if ka_time was nonzero, after the timeout expires how many
 *		times to try to get a response from the peer before giving up
 *		and killing the connection
 * @ka_interval: if ka_time was nonzero, how long to wait before each ka_probes
 *		attempt
 */

struct lws_context_creation_info {
	int port;
	const char *iface;
	struct libwebsocket_protocols *protocols;
	struct libwebsocket_extension *extensions;
    struct lws_token_limits *token_limits;
	const char *ssl_cert_filepath;
	const char *ssl_private_key_filepath;
	const char *ssl_ca_filepath;
	const char *ssl_cipher_list;
	const char *http_proxy_address;
	unsigned int http_proxy_port;
	int gid;
	int uid;
	unsigned int options;
	void *user;
	int ka_time;
	int ka_probes;
	int ka_interval;

};

LWS_VISIBLE LWS_EXTERN
void lws_set_log_level(int level,
			void (*log_emit_function)(int level, const char *line));

LWS_VISIBLE LWS_EXTERN void
lwsl_emit_syslog(int level, const char *line);

LWS_VISIBLE LWS_EXTERN struct libwebsocket_context *
libwebsocket_create_context(struct lws_context_creation_info *info);
	
LWS_VISIBLE LWS_EXTERN int
libwebsocket_set_proxy(struct libwebsocket_context *context, const char *proxy);

LWS_VISIBLE LWS_EXTERN void
libwebsocket_context_destroy(struct libwebsocket_context *context);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_service(struct libwebsocket_context *context, int timeout_ms);

LWS_VISIBLE LWS_EXTERN void
libwebsocket_cancel_service(struct libwebsocket_context *context);

#ifdef LWS_USE_LIBEV
LWS_VISIBLE LWS_EXTERN int
libwebsocket_initloop(
	struct libwebsocket_context *context, struct ev_loop *loop);

LWS_VISIBLE void
libwebsocket_sigint_cb(
	struct ev_loop *loop, struct ev_signal *watcher, int revents);
#endif /* LWS_USE_LIBEV */

LWS_VISIBLE LWS_EXTERN int
libwebsocket_service_fd(struct libwebsocket_context *context,
							 struct libwebsocket_pollfd *pollfd);

LWS_VISIBLE LWS_EXTERN void *
libwebsocket_context_user(struct libwebsocket_context *context);

enum pending_timeout {
	NO_PENDING_TIMEOUT = 0,
	PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
	PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE,
	PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
	PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
	PENDING_TIMEOUT_AWAITING_PING,
	PENDING_TIMEOUT_CLOSE_ACK,
	PENDING_TIMEOUT_AWAITING_EXTENSION_CONNECT_RESPONSE,
	PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
	PENDING_TIMEOUT_SSL_ACCEPT,
	PENDING_TIMEOUT_HTTP_CONTENT,
	PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
};

LWS_VISIBLE LWS_EXTERN void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					 enum pending_timeout reason, int secs);

/*
 * IMPORTANT NOTICE!
 *
 * When sending with websocket protocol (LWS_WRITE_TEXT or LWS_WRITE_BINARY)
 * the send buffer has to have LWS_SEND_BUFFER_PRE_PADDING bytes valid BEFORE
 * buf, and LWS_SEND_BUFFER_POST_PADDING bytes valid AFTER (buf + len).
 *
 * This allows us to add protocol info before and after the data, and send as
 * one packet on the network without payload copying, for maximum efficiency.
 *
 * So for example you need this kind of code to use libwebsocket_write with a
 * 128-byte payload
 *
 *   char buf[LWS_SEND_BUFFER_PRE_PADDING + 128 + LWS_SEND_BUFFER_POST_PADDING];
 *
 *   // fill your part of the buffer... for example here it's all zeros
 *   memset(&buf[LWS_SEND_BUFFER_PRE_PADDING], 0, 128);
 *
 *   libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], 128,
 *   								LWS_WRITE_TEXT);
 *
 * When sending LWS_WRITE_HTTP, there is no protocol addition and you can just
 * use the whole buffer without taking care of the above.
 */

/*
 * this is the frame nonce plus two header plus 8 length
 *   there's an additional two for mux extension per mux nesting level
 * 2 byte prepend on close will already fit because control frames cannot use
 * the big length style
 */

#define LWS_SEND_BUFFER_PRE_PADDING (4 + 10 + (2 * MAX_MUX_RECURSION))
#define LWS_SEND_BUFFER_POST_PADDING 4

LWS_VISIBLE LWS_EXTERN int
libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf, size_t len,
				     enum libwebsocket_write_protocol protocol);

/* helper for case where buffer may be const */
#define libwebsocket_write_http(wsi, buf, len) \
	libwebsocket_write(wsi, (unsigned char *)(buf), len, LWS_WRITE_HTTP)

LWS_VISIBLE LWS_EXTERN int
libwebsockets_serve_http_file(struct libwebsocket_context *context,
			struct libwebsocket *wsi, const char *file,
			const char *content_type, const char *other_headers);
LWS_VISIBLE LWS_EXTERN int
libwebsockets_serve_http_file_fragment(struct libwebsocket_context *context,
			struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int libwebsockets_return_http_status(
		struct libwebsocket_context *context,
			struct libwebsocket *wsi, unsigned int code,
							const char *html_body);

LWS_VISIBLE LWS_EXTERN const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_callback_on_writable(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_callback_on_writable_all_protocol(
				 const struct libwebsocket_protocols *protocol);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_callback_all_protocol(
		const struct libwebsocket_protocols *protocol, int reason);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_get_socket_fd(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_is_final_fragment(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN unsigned char
libwebsocket_get_reserved_bits(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable);

LWS_VISIBLE LWS_EXTERN void
libwebsocket_rx_flow_allow_all_protocol(
				const struct libwebsocket_protocols *protocol);

LWS_VISIBLE LWS_EXTERN size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN struct libwebsocket *
libwebsocket_client_connect(struct libwebsocket_context *clients,
			      const char *address,
			      int port,
			      int ssl_connection,
			      const char *path,
			      const char *host,
			      const char *origin,
			      const char *protocol,
			      int ietf_version_or_minus_one);

LWS_VISIBLE LWS_EXTERN struct libwebsocket *
libwebsocket_client_connect_extended(struct libwebsocket_context *clients,
			      const char *address,
			      int port,
			      int ssl_connection,
			      const char *path,
			      const char *host,
			      const char *origin,
			      const char *protocol,
			      int ietf_version_or_minus_one,
			      void *userdata);

LWS_VISIBLE LWS_EXTERN const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *context);


LWS_VISIBLE LWS_EXTERN void
libwebsockets_get_peer_addresses(struct libwebsocket_context *context,
		struct libwebsocket *wsi, int fd, char *name, int name_len,
					char *rip, int rip_len);

LWS_VISIBLE LWS_EXTERN int
libwebsockets_get_random(struct libwebsocket_context *context,
							    void *buf, int len);

LWS_VISIBLE LWS_EXTERN int
lws_daemonize(const char *_lock_path);

LWS_VISIBLE LWS_EXTERN int
lws_send_pipe_choked(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_frame_is_binary(struct libwebsocket *wsi);

LWS_VISIBLE LWS_EXTERN unsigned char *
libwebsockets_SHA1(const unsigned char *d, size_t n, unsigned char *md);

LWS_VISIBLE LWS_EXTERN int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size);

LWS_VISIBLE LWS_EXTERN int
lws_b64_decode_string(const char *in, char *out, int out_size);

LWS_VISIBLE LWS_EXTERN const char *
lws_get_library_version(void);

/* access to headers... only valid while headers valid */

LWS_VISIBLE LWS_EXTERN int
lws_hdr_total_length(struct libwebsocket *wsi, enum lws_token_indexes h);

LWS_VISIBLE LWS_EXTERN int
lws_hdr_copy(struct libwebsocket *wsi, char *dest, int len,
						enum lws_token_indexes h);

/*
 * Note: this is not normally needed as a user api.  It's provided in case it is
 * useful when integrating with other app poll loop service code.
 */

LWS_VISIBLE LWS_EXTERN int
libwebsocket_read(struct libwebsocket_context *context,
				struct libwebsocket *wsi,
					       unsigned char *buf, size_t len);

#ifndef LWS_NO_EXTENSIONS
LWS_VISIBLE LWS_EXTERN struct libwebsocket_extension *libwebsocket_get_internal_extensions();
#endif

#ifdef __cplusplus
}
#endif

#endif

#endif //ifndef WEBSOCKET_AMALGATED_H_INCLUDED

/* gateY code
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#include "gatey.hpp"
/***************************************************
 * src/Log.hpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_LOG_HPP
#define GATEY_LOG_HPP

//#define GATEY_LOG_ENABLED

#ifdef GATEY_LOG_ENABLED

#include <string>

namespace gatey {
    void log(const char* str);
    void log(std::string const& str);
}

#define GATEY_LOG(str) gatey::log(str)

#else //GATEY_LOG_ENABLED
#define GATEY_LOG (void)
#endif //GATEY_LOG_ENABLED


#endif //GATEY_LOG_HPP
/***************************************************
 * src/GateY.cpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "GateY.hpp"
#include "WebSocketQueue.hpp"
#include "Log.hpp"

#include "json.hpp"
#endif

#include <algorithm>
#include <iostream>
#include <functional>

namespace gatey {

    std::shared_ptr<GateY> global;



    GateY::GateY() :
        stateModified_(false)
    {
        start();
    }

    GateY::~GateY() {
        running_ = false;
#if defined(_MSC_VER)
        //TODO: Hack to fix bug in MSVC
        //thread::join deadlocks if called after exit of main() 
        //see: https://connect.microsoft.com/VisualStudio/feedback/details/747145/std-thread-join-hangs-if-called-after-main-exits-when-using-vs2012-rc
        //wait till thead has finished it's work by locking mutexThreadRunning_ which is locked while thread_ is working
        //and then detach the thread so thread::~thread doesn't abort
        std::lock_guard<std::mutex> bugGuard(mutexThreadRunning_);
        thread_.detach();
#else
        if (thread_.joinable())
            thread_.join();
#endif
    }

    void GateY::sendStateUnsynced() {
        Json::Value jMessage(Json::objectValue);
        jMessage["cmd"] = "state";

        Json::Value jSubscriptions(Json::arrayValue);
        for (Subscription const& subscription : subscriptions_) {
            Json::Value jSubscription(Json::objectValue);
            jSubscription["name"] = Json::Value(subscription.name_);
            jSubscriptions.append(jSubscription);
        }
        jMessage["subscriptions"] = jSubscriptions;

        Json::Value jEmitters(Json::arrayValue);
        for (Emitter const& emitter : emitters_) {
            Json::Value jEmitter(Json::objectValue);
            jEmitter["name"] = Json::Value(emitter.name_);
            jEmitters.append(jEmitter);
        }
        jMessage["emitters"] = jEmitters;

        std::set<SessionId> sessions = webSocket_->sessions();
        sendUnsynced(sessions, jMessage);
    }

    void GateY::handleMessageUnsynced(InMessage const& message) {
        Json::Reader reader;
        Json::Value jMessage;
        reader.parse(message.content(), jMessage);

        std::string cmd = jMessage["cmd"].asString();
        if (cmd == "state") {
//            auto f = has(&Emitter::name, std::string("str"));
//            auto f = std::bind(RemoteSubscription::hasSessionId, id);

            
            eraseRemoteSubscriptionsUnsynced(message.source());
            Json::Value const& jSubscriptions = jMessage["subscriptions"];
            for (Json::Value const& jSubscription : jSubscriptions) {
                std::string name = jSubscription["name"].asString();
                remoteSubscriptions_.emplace_back(std::move(name), message.source());
            }

            
            eraseRemoteEmitters(message.source());
            Json::Value const& jEmitters = jMessage["emitters"];
            for (Json::Value const& jEmitter : jEmitters) {
                std::string name = jEmitter["name"].asString();
                remoteEmitters_.emplace_back(std::move(name), message.source());
            }
        }
        else if (cmd == "message") {
            std::string name = jMessage["name"].asString();
            auto found = findSubscriptionUnsynced(name);
            if (found == subscriptions_.end()) {
                GATEY_LOG("received message without port");
                return;
            }

            Subscription& subscription = *found;

            //RETARDED
            Json::Value const& jValue = jMessage["content"];
            if (subscription.receive_ != nullptr) {
                //TODO: Copies jValue, create callback class and use move constructor (swap because JsonCpp doesn't
                //support move semantics
                callbacks_.push_back(std::bind(subscription.receive_, jValue));
                //gate.receive_(content);
            }

        }
        else if (cmd == "init") {
            //! TODO: Not really necessary, add callback to WebSocketQueue on connected
            sendStateUnsynced();
        }
    }

    void GateY::processCallbacks() {
        std::vector<std::function<void()>> callbacks;
        {
            std::lock_guard<std::mutex> guard(mutex_);
            callbacks = std::move(callbacks_);
        }

        for (std::function<void()>& callback : callbacks)
            callback();
    }

    void GateY::work() {
        {
            std::lock_guard<std::mutex> guard(mutex_);

            if (webSocket_ == nullptr)
                return;

            if (stateModified_) {
                sendStateUnsynced();
                stateModified_ = false;
            }

            //TODO: Not thread safe, DONE
            std::deque<InMessage> messages = webSocket_->receive();
            for (InMessage const& message : messages) {
                handleMessageUnsynced(message);
            }
        }

        //TODO: Check if syncing necessary
        webSocket_->work();

        processCallbacks();
    }


    void GateY::subscribe(std::string const& name, std::function<void(Json::Value const& jValue)> receive) {
        std::lock_guard<std::mutex> guard(mutex_);

        auto found = findSubscriptionUnsynced(name);
        if (found != subscriptions_.end()) {
            //Gate with this name already exists just changing callback
            Subscription& subscription = *found;
            subscription.receive_ = receive;
            return;
        }

        //Subscription subscription(receive);
        subscriptions_.emplace_back(std::move(name), std::move(receive));
        stateModified_ = true;
    }

    void GateY::openEmitter(std::string const& name) {
        std::lock_guard<std::mutex> guard(mutex_);

        auto found = findEmitterUnsynced(name);
        if (found != emitters_.end()) {
            //Gate with this name already exists just changing callback
            return;
        }

        emitters_.emplace_back(name);
        stateModified_ = true;
    }

    void GateY::sendUnsynced(std::set<SessionId> sessions, Json::Value const& jValue) {
        Json::FastWriter jsonWriter;
        std::string content = jsonWriter.write(jValue);
        OutMessage outMessage(std::move(sessions), std::move(content));
        webSocket_->emit(std::move(outMessage));
    }
    
    void GateY::broadcastUnsynced(Json::Value const& json) {
        std::set<SessionId> allSessions = webSocket_->sessions();
        sendUnsynced(allSessions, json);
    }

    //Send 
    void GateY::emit(std::string const& name, Json::Value const& jValue) {
        auto foundEmitter = findEmitterUnsynced(name);
        if (foundEmitter == emitters_.end()) {
            GATEY_LOG("can't send message, no local send gate open with name: " + name);
            return;
        }

        auto foundRemoteSubscription = findRemoteSubscriptionUnsynced(name);
        if (foundRemoteSubscription == remoteSubscriptions_.end()) {
            GATEY_LOG("can't send message, no remote receive gate open with name: " + name);
            return;
        }

        Json::Value message;
        message["cmd"] = "message";
        message["name"] = name;
        message["content"] = jValue;
        
        std::set<SessionId> sessions = collectRemoteSubscriptions(name);
        std::vector<SessionId> deb(sessions.begin(), sessions.end());
        sendUnsynced(sessions, message);
    }

    void GateY::unsubscribeUnsynced(std::string const& name) {
        auto found = findSubscriptionUnsynced(name);
        if (found == subscriptions_.end()) {
            GATEY_LOG("no gate to delete with name: " + name);
            return;
        }

        subscriptions_.erase(found);
        stateModified_ = true;
    }

    void GateY::closeEmitterUnsynced(std::string const& name) {
        auto found = findEmitterUnsynced(name);
        if (found == emitters_.end()) {
            GATEY_LOG("no gate to close with name: " + name);
            return;
        }

        emitters_.erase(found);
        stateModified_ = true;
    }

    void GateY::unsubscribe(std::string const& name) {
        std::lock_guard<std::mutex> guard(mutex_);
        unsubscribeUnsynced(name);
    }

    void GateY::closeEmitter(std::string const& name) {
        std::lock_guard<std::mutex> guard(mutex_);
        closeEmitterUnsynced(name);
    }

    void GateY::start() {
        //TODO: Does this work? libwebsocket is not thread safe (does it work if accessed from different threads?
        webSocket_.reset(new WebSocketQueue());

        running_ = true;
        thread_ = std::thread([this] {
            {
#if defined(_MSC_VER)
                std::lock_guard<std::mutex> bugGuard(mutexThreadRunning_);
#endif

                while (running_) {
                    work();
                }
            }
        });


    }
    
    std::vector<Subscription>::iterator
    GateY::findSubscriptionUnsynced(std::string const& name) {
        return std::find_if(subscriptions_.begin(), subscriptions_.end(),
            [&name](Subscription const& subscription)
            {
                return subscription.name_ == name;
            });
    }
    
    std::vector<Emitter>::iterator
    GateY::findEmitterUnsynced(std::string const& name) {
        return std::find_if(emitters_.begin(), emitters_.end(),
            [&name](Emitter const& emitter)
            {
                return emitter.name_ == name;
            });
    }
    
    std::vector<RemoteEmitter>::iterator
    GateY::findRemoteEmitterUnsynced(std::string const& name) {
        return std::find_if(remoteEmitters_.begin(), remoteEmitters_.end(),
            [&name](RemoteEmitter const& remoteEmitter)
            {
                return remoteEmitter.name_ == name;
            });
    }
    
    std::vector<RemoteSubscription>::iterator
    GateY::findRemoteSubscriptionUnsynced(std::string const& name) {
        return std::find_if(remoteSubscriptions_.begin(), remoteSubscriptions_.end(),
            [&name](RemoteSubscription const& remoteSubscription)
            {
                return remoteSubscription.name_ == name;
            });
    }
    
    std::set<SessionId>
    GateY::collectRemoteSubscriptions(std::string const& name) {
        std::set<SessionId> sessions;
        for(RemoteSubscription const& remoteSubscription : remoteSubscriptions_) {
            if(remoteSubscription.name_ == name)
                sessions.insert(remoteSubscription.sessionId_);
        }
        return sessions;
    }
    
    void GateY::eraseRemoteSubscriptionsUnsynced(SessionId sessionId) {
        auto newEnd = std::remove_if(remoteSubscriptions_.begin(), remoteSubscriptions_.end(),
            [sessionId](RemoteSubscription const& elem)
            {
                return elem.sessionId_ == sessionId;
            });
        remoteSubscriptions_.erase(newEnd, remoteSubscriptions_.end());
    }
    
    void GateY::eraseRemoteEmitters(SessionId sessionId) {
        auto newEnd = std::remove_if(remoteEmitters_.begin(), remoteEmitters_.end(),
            [sessionId](RemoteEmitter const& elem)
            {
                return elem.sessionId_ == sessionId;
            });
        remoteEmitters_.erase(newEnd, remoteEmitters_.end());
    }

}

/***************************************************
 * src/Log.cpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "Log.hpp"
#endif

#include <string>
#include <iostream>

namespace gatey {
    void log(const char* str) {
        std::cout << str << std::endl;
    }

    void log(std::string const& str) {
        std::cout << str << std::endl;
    }
}


/***************************************************
 * src/Serialize.cpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "Serialize.hpp"
#include "json.hpp"
#endif

#include <cmath>
#include <cassert>
#include <iostream>

//Another fun VS 2012 fix
#if defined(_MSC_VER) && (_MSC_VER < 1800) //1800 is Visual Studio 2013
#include <float.h>
#define ISFINITE(arg) _finite((arg))
#else
#define ISFINITE(arg) std::isfinite((arg))
#endif

namespace gatey {
    
    namespace serialize {
        
        //int
        void write(int value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, int& value, Info const& info) {
            value = jValue.asInt();
        }
        
        
        //float
        void write(float value, Json::Value& jValue, Info const& info) {
            if (!ISFINITE(value)) {
                jValue = Json::Value(0.0f);
                std::cerr << "encountered nan or inf" << std::endl;
            }
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, float& value, Info const& info) {
            value = jValue.asFloat();
        }
        
        //double
        void write(double value, Json::Value& jValue, Info const& info) {
            if (!ISFINITE(value)) {
                jValue = Json::Value(0.0f);
                std::cerr << "encountered nan or inf" << std::endl;
            }
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, double& value, Info const& info) {
            value = jValue.asDouble();
        }
        
        //char
        void write(char value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(std::string(value, 1));
        }
        
        void read(Json::Value const& jValue, char& value, Info const& info) {
            //TODO: Check if single char
            value = jValue.asCString()[0];
        }
        
        //std::string
        void write(std::string const& value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, std::string& value, Info const& info) {
            value = jValue.asString();
        }

    } // namespace serialize




} // namespace gatey

/***************************************************
 * src/WebSocketQueue.cpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "WebSocketQueue.hpp"
#include "Log.hpp"

#include "libwebsockets.h"
#endif

#include <iostream>
#include <algorithm>

#if defined(__GNUC__)
//GCC warns about st = {0}, annoying
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif



namespace gatey {

    OutMessage::OutMessage() {
    }
    
    OutMessage::OutMessage(std::set<SessionId> destinations, std::string content) :
        content_(std::move(content)),
        destionations_(std::move(destinations))
    {
        buffer_ = std::vector<char>(content_.size() + LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING);
        std::copy(content_.begin(), content_.end(), buffer_.begin() + LWS_SEND_BUFFER_PRE_PADDING);
        len_ = content_.size();
    }

    OutMessage::OutMessage(OutMessage&& other) :
        content_(std::move(other.content_)),
        destionations_(std::move(other.destionations_)),
        buffer_(std::move(other.buffer_)),
        len_(other.len_)
    {
    }

    OutMessage& OutMessage::operator=(OutMessage&& other) {
        content_ = std::move(other.content_);
        destionations_ = std::move(other.destionations_);
        buffer_ = std::move(other.buffer_);
        len_ = other.len_;
        return *this;
    }
    
    void OutMessage::removeDestination(SessionId sessionId) {
        destionations_.erase(sessionId);
    }

    //TODO: Slow and wasteful
    void OutMessage::keepDestinations(std::set<SessionId> const& keep) {
        std::set<SessionId> kept;
        for (SessionId id : destionations_)
            if (keep.find(id) != keep.end())
                kept.insert(id);
        destionations_ = std::move(kept);
    }
    
    InMessage::InMessage() :
        source_(0)
    {
    }
    
    InMessage::InMessage(SessionId source, char const* bytes, std::size_t len) :
        source_(source),
        content_(bytes, bytes + len)
    {
    }

    struct PerSession {
        SessionId sessionId;

        PerSession(SessionId sessionId) : sessionId(sessionId) {
        }
    };

    struct LibWebsocketsCallbackReasonBoxed {
        libwebsocket_callback_reasons value;
    };

    int callback_impl(libwebsocket_context *context, libwebsocket *wsi,
                      libwebsocket_callback_reasons reason, void *user,
                      void *in, size_t len);
    
//    int callback(libwebsocket_context *context, libwebsocket *wsi,
//                 LibWebsocketsCallbackReasonBoxed const& reasonBoxed,
//                 void *user, void *in, size_t len);

    static libwebsocket_protocols protocols[] = {
        { "gatey", &callback_impl, sizeof(PerSession), 0 },
        { 0 }
    };

    static libwebsocket_protocols *webSocketProtocol = &protocols[0];

    //Called in the server thread
    int callback_impl(libwebsocket_context *context, libwebsocket *wsi,
                      libwebsocket_callback_reasons reason, void *user,
                      void *in, size_t len)
    {
        LibWebsocketsCallbackReasonBoxed reasonBoxed = { reason };
        return WebSocketQueue::callback(context, wsi, reasonBoxed, user, in, len);
    }

    int WebSocketQueue::callback(libwebsocket_context *context, libwebsocket *wsi,
                                 LibWebsocketsCallbackReasonBoxed const& reasonBoxed,
                                 void *user, void *in, size_t len)
    {
        WebSocketQueue *self = (WebSocketQueue*)libwebsocket_context_user(context);
        PerSession *perSession = (PerSession*)user;
        libwebsocket_callback_reasons reason = reasonBoxed.value;

        // reason for callback
        switch (reason) {
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
            if (self->sessions_.size() >= self->maxSessionCount_) {
                GATEY_LOG("not accepting connection because already connected");
                return -1;
            }
            break;
        }
        case LWS_CALLBACK_ESTABLISHED:
            *perSession = PerSession(self->nextUniqueSessionId_);
            self->nextUniqueSessionId_++;
            self->sessions_.insert(perSession->sessionId);
            if (self->sessions_.size() > self->maxSessionCount_) {
                GATEY_LOG("connection established but will be canceled" + std::to_string(perSession->sessionId));
                return -1;
            }

            GATEY_LOG("connection established" + std::to_string(perSession->sessionId));
            break;
        case LWS_CALLBACK_RECEIVE: {
            char const* bytes = (char const*)in;
            InMessage inMessage(perSession->sessionId, bytes, len);
            self->inMessages_.push_back(std::move(inMessage));

            GATEY_LOG("received message");
            break;
        }
        case LWS_CALLBACK_SERVER_WRITEABLE: {
            //Send messages from the queue
            auto found = self->firstMessageWithDestination(perSession->sessionId);
            if (found == self->outMessages_.end())
                break;
            
            OutMessage& message = *found;
            libwebsocket_write(wsi, (unsigned char*)&message.buffer_[LWS_SEND_BUFFER_PRE_PADDING], message.len_, LWS_WRITE_TEXT);
            
            message.removeDestination(perSession->sessionId);
            self->messageSent_ = true;
            break;
        }
        case LWS_CALLBACK_CLOSED: {
            self->sessions_.erase(perSession->sessionId);
            for(OutMessage& outMessage : self->outMessages_) {
                outMessage.removeDestination(perSession->sessionId);
            }
            
            //TODO: Remove already received messages? no
//            std::remove_if(self->inMessages_.begin(), self->inMessages_.end(),
//                           [sessionId](InMessage const& message)
//            {
//                return message.sessionId_ == sessionId;
//            });
            
            GATEY_LOG("connection closed" + std::to_string(perSession->sessionId));
            break;
        }

        default: break;
        }

        return 0;
    }

    WebSocketQueue::WebSocketQueue() :
        messageSent_(false),
        nextUniqueSessionId_(0),
        maxSessionCount_(10)
    {


        //httpProtocol = &protocols[0];
        //webSocketProtocol_ = &protocols_[0];

        // server url will be ws://localhost:9000
        int port = 9000;

        lws_set_log_level(7, lwsl_emit_syslog);

        // create connection struct
        lws_context_creation_info info = { 0 };
        info.port = port;
        info.iface = nullptr;
        info.protocols = protocols;
        info.extensions = nullptr;
        info.ssl_cert_filepath = nullptr;
        info.ssl_private_key_filepath = nullptr;
        info.options = 0;
        info.user = this;

        // create libwebsocket context representing this server
        context_ = libwebsocket_create_context(&info);

        // make sure it starts
        if (context_ == NULL) {
            GATEY_LOG("libwebsocket init failed");
            //TODO: throw exception
            return;
        }

        GATEY_LOG("starting server...");
    }

    WebSocketQueue::~WebSocketQueue() {
        libwebsocket_context_destroy(context_);
    }

    void WebSocketQueue::work() {
        std::lock_guard<std::mutex> guard(mutex_);

        //TODO: Check if any out messages, HAAAAAACK
        //std::cout << "outMessages.size()" << outMessages.size() << std::endl;
        //std::size_t outMessageCount = outMessages_.size();
        while (!outMessages_.empty()) {
            libwebsocket_callback_on_writable_all_protocol(webSocketProtocol);
            messageSent_ = false;
            libwebsocket_service(context_, 0);

            if (!messageSent_)
                break;
        }

        //Cleanup
        for (OutMessage& message : outMessages_) {
            message.keepDestinations(sessions_);
        }

        auto newEnd = std::remove_if(outMessages_.begin(), outMessages_.end(), [](OutMessage const& message) {
            return message.destinations().empty();
        });
        outMessages_.erase(newEnd, outMessages_.end());

        libwebsocket_service(context_, 10);
    }

    void WebSocketQueue::emit(OutMessage message) {
        std::lock_guard<std::mutex> guard(mutex_);
        outMessages_.push_back(std::move(message));
    }

    std::deque<InMessage> WebSocketQueue::receive() {
        std::lock_guard<std::mutex> guard(mutex_);

        std::deque<InMessage> result(std::move(inMessages_));
        return result;
    }
    
    std::set<SessionId> WebSocketQueue::sessions() const {
        std::lock_guard<std::mutex> guard(mutex_);
        
        std::set<SessionId> sessions(sessions_);
        return sessions;
    }
    
    std::deque<OutMessage>::iterator
    WebSocketQueue::firstMessageWithDestination(SessionId sessionId) {
        return std::find_if(outMessages_.begin(), outMessages_.end(),
            [sessionId](OutMessage const& outMessage)
            {
                return outMessage.destionations_.find(sessionId) != outMessage.destionations_.end();
            });
    }

}


/* jsoncpp code
 * Copyright 2007-2010 Baptiste Lepilleur
 * Distributed under MIT license, or public domain if desired and
 */

/***************************************************
 * src/json.cpp
 ***************************************************/

/// Json-cpp amalgated source (http://jsoncpp.sourceforge.net/).
#ifndef GATEY_IS_AMALGAMATION
#include "json.hpp"
#endif
/***************************************************
 * external/jsoncpp/src/lib_json/json_tool.h
 ***************************************************/

// Copyright 2007-2010 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

#ifndef LIB_JSONCPP_JSON_TOOL_H_INCLUDED
#define LIB_JSONCPP_JSON_TOOL_H_INCLUDED

/* This header provides common string manipulation support, such as UTF-8,
 * portable conversion from/to string...
 *
 * It is an internal header that must not be exposed.
 */

namespace Json {

/// Converts a unicode code-point to UTF-8.
static inline std::string codePointToUTF8(unsigned int cp) {
  std::string result;

  // based on description from http://en.wikipedia.org/wiki/UTF-8

  if (cp <= 0x7f) {
    result.resize(1);
    result[0] = static_cast<char>(cp);
  } else if (cp <= 0x7FF) {
    result.resize(2);
    result[1] = static_cast<char>(0x80 | (0x3f & cp));
    result[0] = static_cast<char>(0xC0 | (0x1f & (cp >> 6)));
  } else if (cp <= 0xFFFF) {
    result.resize(3);
    result[2] = static_cast<char>(0x80 | (0x3f & cp));
    result[1] = 0x80 | static_cast<char>((0x3f & (cp >> 6)));
    result[0] = 0xE0 | static_cast<char>((0xf & (cp >> 12)));
  } else if (cp <= 0x10FFFF) {
    result.resize(4);
    result[3] = static_cast<char>(0x80 | (0x3f & cp));
    result[2] = static_cast<char>(0x80 | (0x3f & (cp >> 6)));
    result[1] = static_cast<char>(0x80 | (0x3f & (cp >> 12)));
    result[0] = static_cast<char>(0xF0 | (0x7 & (cp >> 18)));
  }

  return result;
}

/// Returns true if ch is a control character (in range [0,32[).
static inline bool isControlCharacter(char ch) { return ch > 0 && ch <= 0x1F; }

enum {
  /// Constant that specify the size of the buffer that must be passed to
  /// uintToString.
  uintToStringBufferSize = 3 * sizeof(LargestUInt) + 1
};

// Defines a char buffer for use with uintToString().
typedef char UIntToStringBuffer[uintToStringBufferSize];

/** Converts an unsigned integer to string.
 * @param value Unsigned interger to convert to string
 * @param current Input/Output string buffer.
 *        Must have at least uintToStringBufferSize chars free.
 */
static inline void uintToString(LargestUInt value, char *&current) {
  *--current = 0;
  do {
    *--current = char(value % 10) + '0';
    value /= 10;
  } while (value != 0);
}

/** Change ',' to '.' everywhere in buffer.
 *
 * We had a sophisticated way, but it did not work in WinCE.
 * @see https://github.com/open-source-parsers/jsoncpp/pull/9
 */
static inline void fixNumericLocale(char* begin, char* end) {
  while (begin < end) {
    if (*begin == ',') {
      *begin = '.';
    }
    ++begin;
  }
}

} // namespace Json {

#endif // LIB_JSONCPP_JSON_TOOL_H_INCLUDED
// vim: et ts=2 sts=2 sw=2 tw=0

/***************************************************
 * external/jsoncpp/src/lib_json/json_reader.cpp
 ***************************************************/

// Copyright 2007-2011 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

#if !defined(JSON_IS_AMALGAMATION)
#include <json/assertions.h>
#include <json/reader.h>
#include <json/value.h>
#include "json_tool.h"
#endif // if !defined(JSON_IS_AMALGAMATION)
#include <utility>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <istream>

#if defined(_MSC_VER) && _MSC_VER >= 1400 // VC++ 8.0
// Disable warning about strdup being deprecated.
#pragma warning(disable : 4996)
#endif

namespace Json {

// Implementation of class Features
// ////////////////////////////////

Features::Features()
    : allowComments_(true), strictRoot_(false),
      allowDroppedNullPlaceholders_(false), allowNumericKeys_(false) {}

Features Features::all() { return Features(); }

Features Features::strictMode() {
  Features features;
  features.allowComments_ = false;
  features.strictRoot_ = true;
  features.allowDroppedNullPlaceholders_ = false;
  features.allowNumericKeys_ = false;
  return features;
}

// Implementation of class Reader
// ////////////////////////////////

static inline bool in(Reader::Char c,
                      Reader::Char c1,
                      Reader::Char c2,
                      Reader::Char c3,
                      Reader::Char c4) {
  return c == c1 || c == c2 || c == c3 || c == c4;
}

static inline bool in(Reader::Char c,
                      Reader::Char c1,
                      Reader::Char c2,
                      Reader::Char c3,
                      Reader::Char c4,
                      Reader::Char c5) {
  return c == c1 || c == c2 || c == c3 || c == c4 || c == c5;
}

static bool containsNewLine(Reader::Location begin, Reader::Location end) {
  for (; begin < end; ++begin)
    if (*begin == '\n' || *begin == '\r')
      return true;
  return false;
}

// Class Reader
// //////////////////////////////////////////////////////////////////

Reader::Reader()
    : errors_(), document_(), begin_(), end_(), current_(), lastValueEnd_(),
      lastValue_(), commentsBefore_(), features_(Features::all()),
      collectComments_() {}

Reader::Reader(const Features &features)
    : errors_(), document_(), begin_(), end_(), current_(), lastValueEnd_(),
      lastValue_(), commentsBefore_(), features_(features), collectComments_() {
}

bool
Reader::parse(const std::string &document, Value &root, bool collectComments) {
  document_ = document;
  const char *begin = document_.c_str();
  const char *end = begin + document_.length();
  return parse(begin, end, root, collectComments);
}

bool Reader::parse(std::istream &sin, Value &root, bool collectComments) {
  // std::istream_iterator<char> begin(sin);
  // std::istream_iterator<char> end;
  // Those would allow streamed input from a file, if parse() were a
  // template function.

  // Since std::string is reference-counted, this at least does not
  // create an extra copy.
  std::string doc;
  std::getline(sin, doc, (char)EOF);
  return parse(doc, root, collectComments);
}

bool Reader::parse(const char *beginDoc,
                   const char *endDoc,
                   Value &root,
                   bool collectComments) {
  if (!features_.allowComments_) {
    collectComments = false;
  }

  begin_ = beginDoc;
  end_ = endDoc;
  collectComments_ = collectComments;
  current_ = begin_;
  lastValueEnd_ = 0;
  lastValue_ = 0;
  commentsBefore_ = "";
  errors_.clear();
  while (!nodes_.empty())
    nodes_.pop();
  nodes_.push(&root);

  bool successful = readValue();
  Token token;
  skipCommentTokens(token);
  if (collectComments_ && !commentsBefore_.empty())
    root.setComment(commentsBefore_, commentAfter);
  if (features_.strictRoot_) {
    if (!root.isArray() && !root.isObject()) {
      // Set error location to start of doc, ideally should be first token found
      // in doc
      token.type_ = tokenError;
      token.start_ = beginDoc;
      token.end_ = endDoc;
      addError(
          "A valid JSON document must be either an array or an object value.",
          token);
      return false;
    }
  }
  return successful;
}

bool Reader::readValue() {
  Token token;
  skipCommentTokens(token);
  bool successful = true;

  if (collectComments_ && !commentsBefore_.empty()) {
    // Remove newline characters at the end of the comments
    size_t lastNonNewline = commentsBefore_.find_last_not_of("\r\n");
    if (lastNonNewline != std::string::npos) {
      commentsBefore_.erase(lastNonNewline + 1);
    } else {
      commentsBefore_.clear();
    }

    currentValue().setComment(commentsBefore_, commentBefore);
    commentsBefore_ = "";
  }

  switch (token.type_) {
  case tokenObjectBegin:
    successful = readObject(token);
    currentValue().setOffsetLimit(current_ - begin_);
    break;
  case tokenArrayBegin:
    successful = readArray(token);
    currentValue().setOffsetLimit(current_ - begin_);
    break;
  case tokenNumber:
    successful = decodeNumber(token);
    break;
  case tokenString:
    successful = decodeString(token);
    break;
  case tokenTrue:
    currentValue() = true;
    currentValue().setOffsetStart(token.start_ - begin_);
    currentValue().setOffsetLimit(token.end_ - begin_);
    break;
  case tokenFalse:
    currentValue() = false;
    currentValue().setOffsetStart(token.start_ - begin_);
    currentValue().setOffsetLimit(token.end_ - begin_);
    break;
  case tokenNull:
    currentValue() = Value();
    currentValue().setOffsetStart(token.start_ - begin_);
    currentValue().setOffsetLimit(token.end_ - begin_);
    break;
  case tokenArraySeparator:
    if (features_.allowDroppedNullPlaceholders_) {
      // "Un-read" the current token and mark the current value as a null
      // token.
      current_--;
      currentValue() = Value();
      currentValue().setOffsetStart(current_ - begin_ - 1);
      currentValue().setOffsetLimit(current_ - begin_);
      break;
    }
  // Else, fall through...
  default:
    currentValue().setOffsetStart(token.start_ - begin_);
    currentValue().setOffsetLimit(token.end_ - begin_);
    return addError("Syntax error: value, object or array expected.", token);
  }

  if (collectComments_) {
    lastValueEnd_ = current_;
    lastValue_ = &currentValue();
  }

  return successful;
}

void Reader::skipCommentTokens(Token &token) {
  if (features_.allowComments_) {
    do {
      readToken(token);
    } while (token.type_ == tokenComment);
  } else {
    readToken(token);
  }
}

bool Reader::expectToken(TokenType type, Token &token, const char *message) {
  readToken(token);
  if (token.type_ != type)
    return addError(message, token);
  return true;
}

bool Reader::readToken(Token &token) {
  skipSpaces();
  token.start_ = current_;
  Char c = getNextChar();
  bool ok = true;
  switch (c) {
  case '{':
    token.type_ = tokenObjectBegin;
    break;
  case '}':
    token.type_ = tokenObjectEnd;
    break;
  case '[':
    token.type_ = tokenArrayBegin;
    break;
  case ']':
    token.type_ = tokenArrayEnd;
    break;
  case '"':
    token.type_ = tokenString;
    ok = readString();
    break;
  case '/':
    token.type_ = tokenComment;
    ok = readComment();
    break;
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
  case '-':
    token.type_ = tokenNumber;
    readNumber();
    break;
  case 't':
    token.type_ = tokenTrue;
    ok = match("rue", 3);
    break;
  case 'f':
    token.type_ = tokenFalse;
    ok = match("alse", 4);
    break;
  case 'n':
    token.type_ = tokenNull;
    ok = match("ull", 3);
    break;
  case ',':
    token.type_ = tokenArraySeparator;
    break;
  case ':':
    token.type_ = tokenMemberSeparator;
    break;
  case 0:
    token.type_ = tokenEndOfStream;
    break;
  default:
    ok = false;
    break;
  }
  if (!ok)
    token.type_ = tokenError;
  token.end_ = current_;
  return true;
}

void Reader::skipSpaces() {
  while (current_ != end_) {
    Char c = *current_;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
      ++current_;
    else
      break;
  }
}

bool Reader::match(Location pattern, int patternLength) {
  if (end_ - current_ < patternLength)
    return false;
  int index = patternLength;
  while (index--)
    if (current_[index] != pattern[index])
      return false;
  current_ += patternLength;
  return true;
}

bool Reader::readComment() {
  Location commentBegin = current_ - 1;
  Char c = getNextChar();
  bool successful = false;
  if (c == '*')
    successful = readCStyleComment();
  else if (c == '/')
    successful = readCppStyleComment();
  if (!successful)
    return false;

  if (collectComments_) {
    CommentPlacement placement = commentBefore;
    if (lastValueEnd_ && !containsNewLine(lastValueEnd_, commentBegin)) {
      if (c != '*' || !containsNewLine(commentBegin, current_))
        placement = commentAfterOnSameLine;
    }

    addComment(commentBegin, current_, placement);
  }
  return true;
}

void
Reader::addComment(Location begin, Location end, CommentPlacement placement) {
  assert(collectComments_);
  if (placement == commentAfterOnSameLine) {
    assert(lastValue_ != 0);
    lastValue_->setComment(std::string(begin, end), placement);
  } else {
    if (!commentsBefore_.empty())
      commentsBefore_ += "\n";
    commentsBefore_ += std::string(begin, end);
  }
}

bool Reader::readCStyleComment() {
  while (current_ != end_) {
    Char c = getNextChar();
    if (c == '*' && *current_ == '/')
      break;
  }
  return getNextChar() == '/';
}

bool Reader::readCppStyleComment() {
  while (current_ != end_) {
    Char c = getNextChar();
    if (c == '\r' || c == '\n')
      break;
  }
  return true;
}

void Reader::readNumber() {
  while (current_ != end_) {
    if (!(*current_ >= '0' && *current_ <= '9') &&
        !in(*current_, '.', 'e', 'E', '+', '-'))
      break;
    ++current_;
  }
}

bool Reader::readString() {
  Char c = 0;
  while (current_ != end_) {
    c = getNextChar();
    if (c == '\\')
      getNextChar();
    else if (c == '"')
      break;
  }
  return c == '"';
}

bool Reader::readObject(Token &tokenStart) {
  Token tokenName;
  std::string name;
  currentValue() = Value(objectValue);
  currentValue().setOffsetStart(tokenStart.start_ - begin_);
  while (readToken(tokenName)) {
    bool initialTokenOk = true;
    while (tokenName.type_ == tokenComment && initialTokenOk)
      initialTokenOk = readToken(tokenName);
    if (!initialTokenOk)
      break;
    if (tokenName.type_ == tokenObjectEnd && name.empty()) // empty object
      return true;
    name = "";
    if (tokenName.type_ == tokenString) {
      if (!decodeString(tokenName, name))
        return recoverFromError(tokenObjectEnd);
    } else if (tokenName.type_ == tokenNumber && features_.allowNumericKeys_) {
      Value numberName;
      if (!decodeNumber(tokenName, numberName))
        return recoverFromError(tokenObjectEnd);
      name = numberName.asString();
    } else {
      break;
    }

    Token colon;
    if (!readToken(colon) || colon.type_ != tokenMemberSeparator) {
      return addErrorAndRecover(
          "Missing ':' after object member name", colon, tokenObjectEnd);
    }
    Value &value = currentValue()[name];
    nodes_.push(&value);
    bool ok = readValue();
    nodes_.pop();
    if (!ok) // error already set
      return recoverFromError(tokenObjectEnd);

    Token comma;
    if (!readToken(comma) ||
        (comma.type_ != tokenObjectEnd && comma.type_ != tokenArraySeparator &&
         comma.type_ != tokenComment)) {
      return addErrorAndRecover(
          "Missing ',' or '}' in object declaration", comma, tokenObjectEnd);
    }
    bool finalizeTokenOk = true;
    while (comma.type_ == tokenComment && finalizeTokenOk)
      finalizeTokenOk = readToken(comma);
    if (comma.type_ == tokenObjectEnd)
      return true;
  }
  return addErrorAndRecover(
      "Missing '}' or object member name", tokenName, tokenObjectEnd);
}

bool Reader::readArray(Token &tokenStart) {
  currentValue() = Value(arrayValue);
  currentValue().setOffsetStart(tokenStart.start_ - begin_);
  skipSpaces();
  if (*current_ == ']') // empty array
  {
    Token endArray;
    readToken(endArray);
    return true;
  }
  int index = 0;
  for (;;) {
    Value &value = currentValue()[index++];
    nodes_.push(&value);
    bool ok = readValue();
    nodes_.pop();
    if (!ok) // error already set
      return recoverFromError(tokenArrayEnd);

    Token token;
    // Accept Comment after last item in the array.
    ok = readToken(token);
    while (token.type_ == tokenComment && ok) {
      ok = readToken(token);
    }
    bool badTokenType =
        (token.type_ != tokenArraySeparator && token.type_ != tokenArrayEnd);
    if (!ok || badTokenType) {
      return addErrorAndRecover(
          "Missing ',' or ']' in array declaration", token, tokenArrayEnd);
    }
    if (token.type_ == tokenArrayEnd)
      break;
  }
  return true;
}

bool Reader::decodeNumber(Token &token) {
  Value decoded;
  if (!decodeNumber(token, decoded))
    return false;
  currentValue() = decoded;
  currentValue().setOffsetStart(token.start_ - begin_);
  currentValue().setOffsetLimit(token.end_ - begin_);
  return true;
}

bool Reader::decodeNumber(Token &token, Value &decoded) {
  bool isDouble = false;
  for (Location inspect = token.start_; inspect != token.end_; ++inspect) {
    isDouble = isDouble || in(*inspect, '.', 'e', 'E', '+') ||
               (*inspect == '-' && inspect != token.start_);
  }
  if (isDouble)
    return decodeDouble(token, decoded);
  // Attempts to parse the number as an integer. If the number is
  // larger than the maximum supported value of an integer then
  // we decode the number as a double.
  Location current = token.start_;
  bool isNegative = *current == '-';
  if (isNegative)
    ++current;
  Value::LargestUInt maxIntegerValue =
      isNegative ? Value::LargestUInt(-Value::minLargestInt)
                 : Value::maxLargestUInt;
  Value::LargestUInt threshold = maxIntegerValue / 10;
  Value::LargestUInt value = 0;
  while (current < token.end_) {
    Char c = *current++;
    if (c < '0' || c > '9')
      return addError("'" + std::string(token.start_, token.end_) +
                          "' is not a number.",
                      token);
    Value::UInt digit(c - '0');
    if (value >= threshold) {
      // We've hit or exceeded the max value divided by 10 (rounded down). If
      // a) we've only just touched the limit, b) this is the last digit, and
      // c) it's small enough to fit in that rounding delta, we're okay.
      // Otherwise treat this number as a double to avoid overflow.
      if (value > threshold || current != token.end_ ||
          digit > maxIntegerValue % 10) {
        return decodeDouble(token, decoded);
      }
    }
    value = value * 10 + digit;
  }
  if (isNegative)
    decoded = -Value::LargestInt(value);
  else if (value <= Value::LargestUInt(Value::maxInt))
    decoded = Value::LargestInt(value);
  else
    decoded = value;
  return true;
}

bool Reader::decodeDouble(Token &token) {
  Value decoded;
  if (!decodeDouble(token, decoded))
    return false;
  currentValue() = decoded;
  currentValue().setOffsetStart(token.start_ - begin_);
  currentValue().setOffsetLimit(token.end_ - begin_);
  return true;
}

bool Reader::decodeDouble(Token &token, Value &decoded) {
  double value = 0;
  const int bufferSize = 32;
  int count;
  int length = int(token.end_ - token.start_);

  // Sanity check to avoid buffer overflow exploits.
  if (length < 0) {
    return addError("Unable to parse token length", token);
  }

  // Avoid using a string constant for the format control string given to
  // sscanf, as this can cause hard to debug crashes on OS X. See here for more
  // info:
  //
  //     http://developer.apple.com/library/mac/#DOCUMENTATION/DeveloperTools/gcc-4.0.1/gcc/Incompatibilities.html
  char format[] = "%lf";

  if (length <= bufferSize) {
    Char buffer[bufferSize + 1];
    memcpy(buffer, token.start_, length);
    buffer[length] = 0;
    count = sscanf(buffer, format, &value);
  } else {
    std::string buffer(token.start_, token.end_);
    count = sscanf(buffer.c_str(), format, &value);
  }

  if (count != 1)
    return addError("'" + std::string(token.start_, token.end_) +
                        "' is not a number.",
                    token);
  decoded = value;
  return true;
}

bool Reader::decodeString(Token &token) {
  std::string decoded;
  if (!decodeString(token, decoded))
    return false;
  currentValue() = decoded;
  currentValue().setOffsetStart(token.start_ - begin_);
  currentValue().setOffsetLimit(token.end_ - begin_);
  return true;
}

bool Reader::decodeString(Token &token, std::string &decoded) {
  decoded.reserve(token.end_ - token.start_ - 2);
  Location current = token.start_ + 1; // skip '"'
  Location end = token.end_ - 1;       // do not include '"'
  while (current != end) {
    Char c = *current++;
    if (c == '"')
      break;
    else if (c == '\\') {
      if (current == end)
        return addError("Empty escape sequence in string", token, current);
      Char escape = *current++;
      switch (escape) {
      case '"':
        decoded += '"';
        break;
      case '/':
        decoded += '/';
        break;
      case '\\':
        decoded += '\\';
        break;
      case 'b':
        decoded += '\b';
        break;
      case 'f':
        decoded += '\f';
        break;
      case 'n':
        decoded += '\n';
        break;
      case 'r':
        decoded += '\r';
        break;
      case 't':
        decoded += '\t';
        break;
      case 'u': {
        unsigned int unicode;
        if (!decodeUnicodeCodePoint(token, current, end, unicode))
          return false;
        decoded += codePointToUTF8(unicode);
      } break;
      default:
        return addError("Bad escape sequence in string", token, current);
      }
    } else {
      decoded += c;
    }
  }
  return true;
}

bool Reader::decodeUnicodeCodePoint(Token &token,
                                    Location &current,
                                    Location end,
                                    unsigned int &unicode) {

  if (!decodeUnicodeEscapeSequence(token, current, end, unicode))
    return false;
  if (unicode >= 0xD800 && unicode <= 0xDBFF) {
    // surrogate pairs
    if (end - current < 6)
      return addError(
          "additional six characters expected to parse unicode surrogate pair.",
          token,
          current);
    unsigned int surrogatePair;
    if (*(current++) == '\\' && *(current++) == 'u') {
      if (decodeUnicodeEscapeSequence(token, current, end, surrogatePair)) {
        unicode = 0x10000 + ((unicode & 0x3FF) << 10) + (surrogatePair & 0x3FF);
      } else
        return false;
    } else
      return addError("expecting another \\u token to begin the second half of "
                      "a unicode surrogate pair",
                      token,
                      current);
  }
  return true;
}

bool Reader::decodeUnicodeEscapeSequence(Token &token,
                                         Location &current,
                                         Location end,
                                         unsigned int &unicode) {
  if (end - current < 4)
    return addError(
        "Bad unicode escape sequence in string: four digits expected.",
        token,
        current);
  unicode = 0;
  for (int index = 0; index < 4; ++index) {
    Char c = *current++;
    unicode *= 16;
    if (c >= '0' && c <= '9')
      unicode += c - '0';
    else if (c >= 'a' && c <= 'f')
      unicode += c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      unicode += c - 'A' + 10;
    else
      return addError(
          "Bad unicode escape sequence in string: hexadecimal digit expected.",
          token,
          current);
  }
  return true;
}

bool
Reader::addError(const std::string &message, Token &token, Location extra) {
  ErrorInfo info;
  info.token_ = token;
  info.message_ = message;
  info.extra_ = extra;
  errors_.push_back(info);
  return false;
}

bool Reader::recoverFromError(TokenType skipUntilToken) {
  int errorCount = int(errors_.size());
  Token skip;
  for (;;) {
    if (!readToken(skip))
      errors_.resize(errorCount); // discard errors caused by recovery
    if (skip.type_ == skipUntilToken || skip.type_ == tokenEndOfStream)
      break;
  }
  errors_.resize(errorCount);
  return false;
}

bool Reader::addErrorAndRecover(const std::string &message,
                                Token &token,
                                TokenType skipUntilToken) {
  addError(message, token);
  return recoverFromError(skipUntilToken);
}

Value &Reader::currentValue() { return *(nodes_.top()); }

Reader::Char Reader::getNextChar() {
  if (current_ == end_)
    return 0;
  return *current_++;
}

void Reader::getLocationLineAndColumn(Location location,
                                      int &line,
                                      int &column) const {
  Location current = begin_;
  Location lastLineStart = current;
  line = 0;
  while (current < location && current != end_) {
    Char c = *current++;
    if (c == '\r') {
      if (*current == '\n')
        ++current;
      lastLineStart = current;
      ++line;
    } else if (c == '\n') {
      lastLineStart = current;
      ++line;
    }
  }
  // column & line start at 1
  column = int(location - lastLineStart) + 1;
  ++line;
}

std::string Reader::getLocationLineAndColumn(Location location) const {
  int line, column;
  getLocationLineAndColumn(location, line, column);
  char buffer[18 + 16 + 16 + 1];
#if defined(_MSC_VER) && defined(__STDC_SECURE_LIB__)
  #if defined(WINCE)
  _snprintf(buffer, sizeof(buffer), "Line %d, Column %d", line, column);
  #else
  sprintf_s(buffer, sizeof(buffer), "Line %d, Column %d", line, column);
  #endif
#else
  snprintf(buffer, sizeof(buffer), "Line %d, Column %d", line, column);
#endif
  return buffer;
}

// Deprecated. Preserved for backward compatibility
std::string Reader::getFormatedErrorMessages() const {
  return getFormattedErrorMessages();
}

std::string Reader::getFormattedErrorMessages() const {
  std::string formattedMessage;
  for (Errors::const_iterator itError = errors_.begin();
       itError != errors_.end();
       ++itError) {
    const ErrorInfo &error = *itError;
    formattedMessage +=
        "* " + getLocationLineAndColumn(error.token_.start_) + "\n";
    formattedMessage += "  " + error.message_ + "\n";
    if (error.extra_)
      formattedMessage +=
          "See " + getLocationLineAndColumn(error.extra_) + " for detail.\n";
  }
  return formattedMessage;
}

std::vector<Reader::StructuredError> Reader::getStructuredErrors() const {
  std::vector<Reader::StructuredError> allErrors;
  for (Errors::const_iterator itError = errors_.begin();
       itError != errors_.end();
       ++itError) {
    const ErrorInfo &error = *itError;
    Reader::StructuredError structured;
    structured.offset_start = error.token_.start_ - begin_;
    structured.offset_limit = error.token_.end_ - begin_;
    structured.message = error.message_;
    allErrors.push_back(structured);
  }
  return allErrors;
}

std::istream &operator>>(std::istream &sin, Value &root) {
  Json::Reader reader;
  bool ok = reader.parse(sin, root, true);
  if (!ok) {
    fprintf(stderr,
            "Error from reader: %s",
            reader.getFormattedErrorMessages().c_str());

    JSON_FAIL_MESSAGE("reader error");
  }
  return sin;
}

} // namespace Json
// vim: et ts=2 sts=2 sw=2 tw=0

/***************************************************
 * external/jsoncpp/src/lib_json/json_batchallocator.h
 ***************************************************/

// Copyright 2007-2010 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

#ifndef JSONCPP_BATCHALLOCATOR_H_INCLUDED
#define JSONCPP_BATCHALLOCATOR_H_INCLUDED

#include <stdlib.h>
#include <assert.h>

#ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION

namespace Json {

/* Fast memory allocator.
 *
 * This memory allocator allocates memory for a batch of object (specified by
 * the page size, the number of object in each page).
 *
 * It does not allow the destruction of a single object. All the allocated
 * objects can be destroyed at once. The memory can be either released or reused
 * for future allocation.
 *
 * The in-place new operator must be used to construct the object using the
 * pointer returned by allocate.
 */
template <typename AllocatedType, const unsigned int objectPerAllocation>
class BatchAllocator {
public:
  BatchAllocator(unsigned int objectsPerPage = 255)
      : freeHead_(0), objectsPerPage_(objectsPerPage) {
    //      printf( "Size: %d => %s\n", sizeof(AllocatedType),
    // typeid(AllocatedType).name() );
    assert(sizeof(AllocatedType) * objectPerAllocation >=
           sizeof(AllocatedType *)); // We must be able to store a slist in the
                                     // object free space.
    assert(objectsPerPage >= 16);
    batches_ = allocateBatch(0); // allocated a dummy page
    currentBatch_ = batches_;
  }

  ~BatchAllocator() {
    for (BatchInfo *batch = batches_; batch;) {
      BatchInfo *nextBatch = batch->next_;
      free(batch);
      batch = nextBatch;
    }
  }

  /// allocate space for an array of objectPerAllocation object.
  /// @warning it is the responsability of the caller to call objects
  /// constructors.
  AllocatedType *allocate() {
    if (freeHead_) // returns node from free list.
    {
      AllocatedType *object = freeHead_;
      freeHead_ = *(AllocatedType **)object;
      return object;
    }
    if (currentBatch_->used_ == currentBatch_->end_) {
      currentBatch_ = currentBatch_->next_;
      while (currentBatch_ && currentBatch_->used_ == currentBatch_->end_)
        currentBatch_ = currentBatch_->next_;

      if (!currentBatch_) // no free batch found, allocate a new one
      {
        currentBatch_ = allocateBatch(objectsPerPage_);
        currentBatch_->next_ = batches_; // insert at the head of the list
        batches_ = currentBatch_;
      }
    }
    AllocatedType *allocated = currentBatch_->used_;
    currentBatch_->used_ += objectPerAllocation;
    return allocated;
  }

  /// Release the object.
  /// @warning it is the responsability of the caller to actually destruct the
  /// object.
  void release(AllocatedType *object) {
    assert(object != 0);
    *(AllocatedType **)object = freeHead_;
    freeHead_ = object;
  }

private:
  struct BatchInfo {
    BatchInfo *next_;
    AllocatedType *used_;
    AllocatedType *end_;
    AllocatedType buffer_[objectPerAllocation];
  };

  // disabled copy constructor and assignement operator.
  BatchAllocator(const BatchAllocator &);
  void operator=(const BatchAllocator &);

  static BatchInfo *allocateBatch(unsigned int objectsPerPage) {
    const unsigned int mallocSize =
        sizeof(BatchInfo) - sizeof(AllocatedType) * objectPerAllocation +
        sizeof(AllocatedType) * objectPerAllocation * objectsPerPage;
    BatchInfo *batch = static_cast<BatchInfo *>(malloc(mallocSize));
    batch->next_ = 0;
    batch->used_ = batch->buffer_;
    batch->end_ = batch->buffer_ + objectsPerPage;
    return batch;
  }

  BatchInfo *batches_;
  BatchInfo *currentBatch_;
  /// Head of a single linked list within the allocated space of freeed object
  AllocatedType *freeHead_;
  unsigned int objectsPerPage_;
};

} // namespace Json

#endif // ifndef JSONCPP_DOC_INCLUDE_IMPLEMENTATION

#endif // JSONCPP_BATCHALLOCATOR_H_INCLUDED
// vim: et ts=2 sts=2 sw=2 tw=0

/***************************************************
 * external/jsoncpp/src/lib_json/json_valueiterator.inl
 ***************************************************/

// Copyright 2007-2010 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

// included by json_value.cpp

namespace Json {

// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class ValueIteratorBase
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

ValueIteratorBase::ValueIteratorBase()
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   : current_()
   , isNull_( true )
{
}
#else
   : isArray_( true )
   , isNull_( true )
{
   iterator_.array_ = ValueInternalArray::IteratorState();
}
#endif


#ifndef JSON_VALUE_USE_INTERNAL_MAP
ValueIteratorBase::ValueIteratorBase( const Value::ObjectValues::iterator &current )
   : current_( current )
   , isNull_( false )
{
}
#else
ValueIteratorBase::ValueIteratorBase( const ValueInternalArray::IteratorState &state )
   : isArray_( true )
{
   iterator_.array_ = state;
}


ValueIteratorBase::ValueIteratorBase( const ValueInternalMap::IteratorState &state )
   : isArray_( false )
{
   iterator_.map_ = state;
}
#endif

Value &
ValueIteratorBase::deref() const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   return current_->second;
#else
   if ( isArray_ )
      return ValueInternalArray::dereference( iterator_.array_ );
   return ValueInternalMap::value( iterator_.map_ );
#endif
}


void 
ValueIteratorBase::increment()
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   ++current_;
#else
   if ( isArray_ )
      ValueInternalArray::increment( iterator_.array_ );
   ValueInternalMap::increment( iterator_.map_ );
#endif
}


void 
ValueIteratorBase::decrement()
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   --current_;
#else
   if ( isArray_ )
      ValueInternalArray::decrement( iterator_.array_ );
   ValueInternalMap::decrement( iterator_.map_ );
#endif
}


ValueIteratorBase::difference_type 
ValueIteratorBase::computeDistance( const SelfType &other ) const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
# ifdef JSON_USE_CPPTL_SMALLMAP
   return current_ - other.current_;
# else
   // Iterator for null value are initialized using the default
   // constructor, which initialize current_ to the default
   // std::map::iterator. As begin() and end() are two instance 
   // of the default std::map::iterator, they can not be compared.
   // To allow this, we handle this comparison specifically.
   if ( isNull_  &&  other.isNull_ )
   {
      return 0;
   }


   // Usage of std::distance is not portable (does not compile with Sun Studio 12 RogueWave STL,
   // which is the one used by default).
   // Using a portable hand-made version for non random iterator instead:
   //   return difference_type( std::distance( current_, other.current_ ) );
   difference_type myDistance = 0;
   for ( Value::ObjectValues::iterator it = current_; it != other.current_; ++it )
   {
      ++myDistance;
   }
   return myDistance;
# endif
#else
   if ( isArray_ )
      return ValueInternalArray::distance( iterator_.array_, other.iterator_.array_ );
   return ValueInternalMap::distance( iterator_.map_, other.iterator_.map_ );
#endif
}


bool 
ValueIteratorBase::isEqual( const SelfType &other ) const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   if ( isNull_ )
   {
      return other.isNull_;
   }
   return current_ == other.current_;
#else
   if ( isArray_ )
      return ValueInternalArray::equals( iterator_.array_, other.iterator_.array_ );
   return ValueInternalMap::equals( iterator_.map_, other.iterator_.map_ );
#endif
}


void 
ValueIteratorBase::copy( const SelfType &other )
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   current_ = other.current_;
   isNull_ = other.isNull_;
#else
   if ( isArray_ )
      iterator_.array_ = other.iterator_.array_;
   iterator_.map_ = other.iterator_.map_;
#endif
}


Value 
ValueIteratorBase::key() const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   const Value::CZString czstring = (*current_).first;
   if ( czstring.c_str() )
   {
      if ( czstring.isStaticString() )
         return Value( StaticString( czstring.c_str() ) );
      return Value( czstring.c_str() );
   }
   return Value( czstring.index() );
#else
   if ( isArray_ )
      return Value( ValueInternalArray::indexOf( iterator_.array_ ) );
   bool isStatic;
   const char *memberName = ValueInternalMap::key( iterator_.map_, isStatic );
   if ( isStatic )
      return Value( StaticString( memberName ) );
   return Value( memberName );
#endif
}


UInt 
ValueIteratorBase::index() const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   const Value::CZString czstring = (*current_).first;
   if ( !czstring.c_str() )
      return czstring.index();
   return Value::UInt( -1 );
#else
   if ( isArray_ )
      return Value::UInt( ValueInternalArray::indexOf( iterator_.array_ ) );
   return Value::UInt( -1 );
#endif
}


const char *
ValueIteratorBase::memberName() const
{
#ifndef JSON_VALUE_USE_INTERNAL_MAP
   const char *name = (*current_).first.c_str();
   return name ? name : "";
#else
   if ( !isArray_ )
      return ValueInternalMap::key( iterator_.map_ );
   return "";
#endif
}


// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class ValueConstIterator
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

ValueConstIterator::ValueConstIterator()
{
}


#ifndef JSON_VALUE_USE_INTERNAL_MAP
ValueConstIterator::ValueConstIterator( const Value::ObjectValues::iterator &current )
   : ValueIteratorBase( current )
{
}
#else
ValueConstIterator::ValueConstIterator( const ValueInternalArray::IteratorState &state )
   : ValueIteratorBase( state )
{
}

ValueConstIterator::ValueConstIterator( const ValueInternalMap::IteratorState &state )
   : ValueIteratorBase( state )
{
}
#endif

ValueConstIterator &
ValueConstIterator::operator =( const ValueIteratorBase &other )
{
   copy( other );
   return *this;
}


// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class ValueIterator
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

ValueIterator::ValueIterator()
{
}


#ifndef JSON_VALUE_USE_INTERNAL_MAP
ValueIterator::ValueIterator( const Value::ObjectValues::iterator &current )
   : ValueIteratorBase( current )
{
}
#else
ValueIterator::ValueIterator( const ValueInternalArray::IteratorState &state )
   : ValueIteratorBase( state )
{
}

ValueIterator::ValueIterator( const ValueInternalMap::IteratorState &state )
   : ValueIteratorBase( state )
{
}
#endif

ValueIterator::ValueIterator( const ValueConstIterator &other )
   : ValueIteratorBase( other )
{
}

ValueIterator::ValueIterator( const ValueIterator &other )
   : ValueIteratorBase( other )
{
}

ValueIterator &
ValueIterator::operator =( const SelfType &other )
{
   copy( other );
   return *this;
}

} // namespace Json
// vim: et ts=3 sts=3 sw=3 tw=0

/***************************************************
 * external/jsoncpp/src/lib_json/json_value.cpp
 ***************************************************/

// Copyright 2011 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

#if !defined(JSON_IS_AMALGAMATION)
#include <json/assertions.h>
#include <json/value.h>
#include <json/writer.h>
#ifndef JSON_USE_SIMPLE_INTERNAL_ALLOCATOR
#include "json_batchallocator.h"
#endif // #ifndef JSON_USE_SIMPLE_INTERNAL_ALLOCATOR
#endif // if !defined(JSON_IS_AMALGAMATION)
#include <math.h>
#include <sstream>
#include <utility>
#include <cstring>
#include <cassert>
#ifdef JSON_USE_CPPTL
#include <cpptl/conststring.h>
#endif
#include <cstddef> // size_t

#define JSON_ASSERT_UNREACHABLE assert(false)

namespace Json {

// This is a walkaround to avoid the static initialization of Value::null.
// kNull must be word-aligned to avoid crashing on ARM.  We use an alignment of
// 8 (instead of 4) as a bit of future-proofing.
#if defined(__ARMEL__)
#define ALIGNAS(byte_alignment) __attribute__((aligned(byte_alignment)))
#else
#define ALIGNAS(byte_alignment)
#endif
static const unsigned char ALIGNAS(8) kNull[sizeof(Value)] = {0};
const Value& Value::null = reinterpret_cast<const Value&>(kNull);

const Int Value::minInt = Int(~(UInt(-1) / 2));
const Int Value::maxInt = Int(UInt(-1) / 2);
const UInt Value::maxUInt = UInt(-1);
#if defined(JSON_HAS_INT64)
const Int64 Value::minInt64 = Int64(~(UInt64(-1) / 2));
const Int64 Value::maxInt64 = Int64(UInt64(-1) / 2);
const UInt64 Value::maxUInt64 = UInt64(-1);
// The constant is hard-coded because some compiler have trouble
// converting Value::maxUInt64 to a double correctly (AIX/xlC).
// Assumes that UInt64 is a 64 bits integer.
static const double maxUInt64AsDouble = 18446744073709551615.0;
#endif // defined(JSON_HAS_INT64)
const LargestInt Value::minLargestInt = LargestInt(~(LargestUInt(-1) / 2));
const LargestInt Value::maxLargestInt = LargestInt(LargestUInt(-1) / 2);
const LargestUInt Value::maxLargestUInt = LargestUInt(-1);

/// Unknown size marker
static const unsigned int unknown = (unsigned)-1;

#if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
template <typename T, typename U>
static inline bool InRange(double d, T min, U max) {
  return d >= min && d <= max;
}
#else  // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
static inline double integerToDouble(Json::UInt64 value) {
  return static_cast<double>(Int64(value / 2)) * 2.0 + Int64(value & 1);
}

template <typename T> static inline double integerToDouble(T value) {
  return static_cast<double>(value);
}

template <typename T, typename U>
static inline bool InRange(double d, T min, U max) {
  return d >= integerToDouble(min) && d <= integerToDouble(max);
}
#endif // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)

/** Duplicates the specified string value.
 * @param value Pointer to the string to duplicate. Must be zero-terminated if
 *              length is "unknown".
 * @param length Length of the value. if equals to unknown, then it will be
 *               computed using strlen(value).
 * @return Pointer on the duplicate instance of string.
 */
static inline char *duplicateStringValue(const char *value,
                                         unsigned int length = unknown) {
  if (length == unknown)
    length = (unsigned int)strlen(value);

  // Avoid an integer overflow in the call to malloc below by limiting length
  // to a sane value.
  if (length >= (unsigned)Value::maxInt)
    length = Value::maxInt - 1;

  char *newString = static_cast<char *>(malloc(length + 1));
  JSON_ASSERT_MESSAGE(newString != 0,
                      "in Json::Value::duplicateStringValue(): "
                      "Failed to allocate string value buffer");
  memcpy(newString, value, length);
  newString[length] = 0;
  return newString;
}

/** Free the string duplicated by duplicateStringValue().
 */
static inline void releaseStringValue(char *value) {
  if (value)
    free(value);
}

} // namespace Json

// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// ValueInternals...
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
#if !defined(JSON_IS_AMALGAMATION)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
#include "json_internalarray.inl"
#include "json_internalmap.inl"
#endif // JSON_VALUE_USE_INTERNAL_MAP

#include "json_valueiterator.inl"
#endif // if !defined(JSON_IS_AMALGAMATION)

namespace Json {

// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class Value::CommentInfo
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

Value::CommentInfo::CommentInfo() : comment_(0) {}

Value::CommentInfo::~CommentInfo() {
  if (comment_)
    releaseStringValue(comment_);
}

void Value::CommentInfo::setComment(const char *text) {
  if (comment_)
    releaseStringValue(comment_);
  JSON_ASSERT(text != 0);
  JSON_ASSERT_MESSAGE(
      text[0] == '\0' || text[0] == '/',
      "in Json::Value::setComment(): Comments must start with /");
  // It seems that /**/ style comments are acceptable as well.
  comment_ = duplicateStringValue(text);
}

// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class Value::CZString
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
#ifndef JSON_VALUE_USE_INTERNAL_MAP

// Notes: index_ indicates if the string was allocated when
// a string is stored.

Value::CZString::CZString(ArrayIndex index) : cstr_(0), index_(index) {}

Value::CZString::CZString(const char *cstr, DuplicationPolicy allocate)
    : cstr_(allocate == duplicate ? duplicateStringValue(cstr) : cstr),
      index_(allocate) {}

Value::CZString::CZString(const CZString &other)
    : cstr_(other.index_ != noDuplication && other.cstr_ != 0
                ? duplicateStringValue(other.cstr_)
                : other.cstr_),
      index_(other.cstr_
                 ? (other.index_ == noDuplication ? noDuplication : duplicate)
                 : other.index_) {}

Value::CZString::~CZString() {
  if (cstr_ && index_ == duplicate)
    releaseStringValue(const_cast<char *>(cstr_));
}

void Value::CZString::swap(CZString &other) {
  std::swap(cstr_, other.cstr_);
  std::swap(index_, other.index_);
}

Value::CZString &Value::CZString::operator=(const CZString &other) {
  CZString temp(other);
  swap(temp);
  return *this;
}

bool Value::CZString::operator<(const CZString &other) const {
  if (cstr_)
    return strcmp(cstr_, other.cstr_) < 0;
  return index_ < other.index_;
}

bool Value::CZString::operator==(const CZString &other) const {
  if (cstr_)
    return strcmp(cstr_, other.cstr_) == 0;
  return index_ == other.index_;
}

ArrayIndex Value::CZString::index() const { return index_; }

const char *Value::CZString::c_str() const { return cstr_; }

bool Value::CZString::isStaticString() const { return index_ == noDuplication; }

#endif // ifndef JSON_VALUE_USE_INTERNAL_MAP

// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// class Value::Value
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

/*! \internal Default constructor initialization must be equivalent to:
 * memset( this, 0, sizeof(Value) )
 * This optimization is used in ValueInternalMap fast allocator.
 */
Value::Value(ValueType type)
    : type_(type), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  switch (type) {
  case nullValue:
    break;
  case intValue:
  case uintValue:
    value_.int_ = 0;
    break;
  case realValue:
    value_.real_ = 0.0;
    break;
  case stringValue:
    value_.string_ = 0;
    break;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue:
    value_.map_ = new ObjectValues();
    break;
#else
  case arrayValue:
    value_.array_ = arrayAllocator()->newArray();
    break;
  case objectValue:
    value_.map_ = mapAllocator()->newMap();
    break;
#endif
  case booleanValue:
    value_.bool_ = false;
    break;
  default:
    JSON_ASSERT_UNREACHABLE;
  }
}

Value::Value(UInt value)
    : type_(uintValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.uint_ = value;
}

Value::Value(Int value)
    : type_(intValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.int_ = value;
}

#if defined(JSON_HAS_INT64)
Value::Value(Int64 value)
    : type_(intValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.int_ = value;
}

Value::Value(UInt64 value)
    : type_(uintValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.uint_ = value;
}
#endif // defined(JSON_HAS_INT64)

Value::Value(double value)
    : type_(realValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.real_ = value;
}

Value::Value(const char *value)
    : type_(stringValue), allocated_(true)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.string_ = duplicateStringValue(value);
}

Value::Value(const char *beginValue, const char *endValue)
    : type_(stringValue), allocated_(true)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.string_ =
      duplicateStringValue(beginValue, (unsigned int)(endValue - beginValue));
}

Value::Value(const std::string &value)
    : type_(stringValue), allocated_(true)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.string_ =
      duplicateStringValue(value.c_str(), (unsigned int)value.length());
}

Value::Value(const StaticString &value)
    : type_(stringValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.string_ = const_cast<char *>(value.c_str());
}

#ifdef JSON_USE_CPPTL
Value::Value(const CppTL::ConstString &value)
    : type_(stringValue), allocated_(true)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.string_ = duplicateStringValue(value, value.length());
}
#endif

Value::Value(bool value)
    : type_(booleanValue), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(0), limit_(0) {
  value_.bool_ = value;
}

Value::Value(const Value &other)
    : type_(other.type_), allocated_(false)
#ifdef JSON_VALUE_USE_INTERNAL_MAP
      ,
      itemIsUsed_(0)
#endif
      ,
      comments_(0), start_(other.start_), limit_(other.limit_) {
  switch (type_) {
  case nullValue:
  case intValue:
  case uintValue:
  case realValue:
  case booleanValue:
    value_ = other.value_;
    break;
  case stringValue:
    if (other.value_.string_) {
      value_.string_ = duplicateStringValue(other.value_.string_);
      allocated_ = true;
    } else {
      value_.string_ = 0;
      allocated_ = false;
    }
    break;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue:
    value_.map_ = new ObjectValues(*other.value_.map_);
    break;
#else
  case arrayValue:
    value_.array_ = arrayAllocator()->newArrayCopy(*other.value_.array_);
    break;
  case objectValue:
    value_.map_ = mapAllocator()->newMapCopy(*other.value_.map_);
    break;
#endif
  default:
    JSON_ASSERT_UNREACHABLE;
  }
  if (other.comments_) {
    comments_ = new CommentInfo[numberOfCommentPlacement];
    for (int comment = 0; comment < numberOfCommentPlacement; ++comment) {
      const CommentInfo &otherComment = other.comments_[comment];
      if (otherComment.comment_)
        comments_[comment].setComment(otherComment.comment_);
    }
  }
}

Value::~Value() {
  switch (type_) {
  case nullValue:
  case intValue:
  case uintValue:
  case realValue:
  case booleanValue:
    break;
  case stringValue:
    if (allocated_)
      releaseStringValue(value_.string_);
    break;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue:
    delete value_.map_;
    break;
#else
  case arrayValue:
    arrayAllocator()->destructArray(value_.array_);
    break;
  case objectValue:
    mapAllocator()->destructMap(value_.map_);
    break;
#endif
  default:
    JSON_ASSERT_UNREACHABLE;
  }

  if (comments_)
    delete[] comments_;
}

Value &Value::operator=(const Value &other) {
  Value temp(other);
  swap(temp);
  return *this;
}

void Value::swap(Value &other) {
  ValueType temp = type_;
  type_ = other.type_;
  other.type_ = temp;
  std::swap(value_, other.value_);
  int temp2 = allocated_;
  allocated_ = other.allocated_;
  other.allocated_ = temp2;
  std::swap(start_, other.start_);
  std::swap(limit_, other.limit_);
}

ValueType Value::type() const { return type_; }

int Value::compare(const Value &other) const {
  if (*this < other)
    return -1;
  if (*this > other)
    return 1;
  return 0;
}

bool Value::operator<(const Value &other) const {
  int typeDelta = type_ - other.type_;
  if (typeDelta)
    return typeDelta < 0 ? true : false;
  switch (type_) {
  case nullValue:
    return false;
  case intValue:
    return value_.int_ < other.value_.int_;
  case uintValue:
    return value_.uint_ < other.value_.uint_;
  case realValue:
    return value_.real_ < other.value_.real_;
  case booleanValue:
    return value_.bool_ < other.value_.bool_;
  case stringValue:
    return (value_.string_ == 0 && other.value_.string_) ||
           (other.value_.string_ && value_.string_ &&
            strcmp(value_.string_, other.value_.string_) < 0);
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue: {
    int delta = int(value_.map_->size() - other.value_.map_->size());
    if (delta)
      return delta < 0;
    return (*value_.map_) < (*other.value_.map_);
  }
#else
  case arrayValue:
    return value_.array_->compare(*(other.value_.array_)) < 0;
  case objectValue:
    return value_.map_->compare(*(other.value_.map_)) < 0;
#endif
  default:
    JSON_ASSERT_UNREACHABLE;
  }
  return false; // unreachable
}

bool Value::operator<=(const Value &other) const { return !(other < *this); }

bool Value::operator>=(const Value &other) const { return !(*this < other); }

bool Value::operator>(const Value &other) const { return other < *this; }

bool Value::operator==(const Value &other) const {
  // if ( type_ != other.type_ )
  // GCC 2.95.3 says:
  // attempt to take address of bit-field structure member `Json::Value::type_'
  // Beats me, but a temp solves the problem.
  int temp = other.type_;
  if (type_ != temp)
    return false;
  switch (type_) {
  case nullValue:
    return true;
  case intValue:
    return value_.int_ == other.value_.int_;
  case uintValue:
    return value_.uint_ == other.value_.uint_;
  case realValue:
    return value_.real_ == other.value_.real_;
  case booleanValue:
    return value_.bool_ == other.value_.bool_;
  case stringValue:
    return (value_.string_ == other.value_.string_) ||
           (other.value_.string_ && value_.string_ &&
            strcmp(value_.string_, other.value_.string_) == 0);
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue:
    return value_.map_->size() == other.value_.map_->size() &&
           (*value_.map_) == (*other.value_.map_);
#else
  case arrayValue:
    return value_.array_->compare(*(other.value_.array_)) == 0;
  case objectValue:
    return value_.map_->compare(*(other.value_.map_)) == 0;
#endif
  default:
    JSON_ASSERT_UNREACHABLE;
  }
  return false; // unreachable
}

bool Value::operator!=(const Value &other) const { return !(*this == other); }

const char *Value::asCString() const {
  JSON_ASSERT_MESSAGE(type_ == stringValue,
                      "in Json::Value::asCString(): requires stringValue");
  return value_.string_;
}

std::string Value::asString() const {
  switch (type_) {
  case nullValue:
    return "";
  case stringValue:
    return value_.string_ ? value_.string_ : "";
  case booleanValue:
    return value_.bool_ ? "true" : "false";
  case intValue:
    return valueToString(value_.int_);
  case uintValue:
    return valueToString(value_.uint_);
  case realValue:
    return valueToString(value_.real_);
  default:
    JSON_FAIL_MESSAGE("Type is not convertible to string");
  }
}

#ifdef JSON_USE_CPPTL
CppTL::ConstString Value::asConstString() const {
  return CppTL::ConstString(asString().c_str());
}
#endif

Value::Int Value::asInt() const {
  switch (type_) {
  case intValue:
    JSON_ASSERT_MESSAGE(isInt(), "LargestInt out of Int range");
    return Int(value_.int_);
  case uintValue:
    JSON_ASSERT_MESSAGE(isInt(), "LargestUInt out of Int range");
    return Int(value_.uint_);
  case realValue:
    JSON_ASSERT_MESSAGE(InRange(value_.real_, minInt, maxInt),
                        "double out of Int range");
    return Int(value_.real_);
  case nullValue:
    return 0;
  case booleanValue:
    return value_.bool_ ? 1 : 0;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to Int.");
}

Value::UInt Value::asUInt() const {
  switch (type_) {
  case intValue:
    JSON_ASSERT_MESSAGE(isUInt(), "LargestInt out of UInt range");
    return UInt(value_.int_);
  case uintValue:
    JSON_ASSERT_MESSAGE(isUInt(), "LargestUInt out of UInt range");
    return UInt(value_.uint_);
  case realValue:
    JSON_ASSERT_MESSAGE(InRange(value_.real_, 0, maxUInt),
                        "double out of UInt range");
    return UInt(value_.real_);
  case nullValue:
    return 0;
  case booleanValue:
    return value_.bool_ ? 1 : 0;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to UInt.");
}

#if defined(JSON_HAS_INT64)

Value::Int64 Value::asInt64() const {
  switch (type_) {
  case intValue:
    return Int64(value_.int_);
  case uintValue:
    JSON_ASSERT_MESSAGE(isInt64(), "LargestUInt out of Int64 range");
    return Int64(value_.uint_);
  case realValue:
    JSON_ASSERT_MESSAGE(InRange(value_.real_, minInt64, maxInt64),
                        "double out of Int64 range");
    return Int64(value_.real_);
  case nullValue:
    return 0;
  case booleanValue:
    return value_.bool_ ? 1 : 0;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to Int64.");
}

Value::UInt64 Value::asUInt64() const {
  switch (type_) {
  case intValue:
    JSON_ASSERT_MESSAGE(isUInt64(), "LargestInt out of UInt64 range");
    return UInt64(value_.int_);
  case uintValue:
    return UInt64(value_.uint_);
  case realValue:
    JSON_ASSERT_MESSAGE(InRange(value_.real_, 0, maxUInt64),
                        "double out of UInt64 range");
    return UInt64(value_.real_);
  case nullValue:
    return 0;
  case booleanValue:
    return value_.bool_ ? 1 : 0;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to UInt64.");
}
#endif // if defined(JSON_HAS_INT64)

LargestInt Value::asLargestInt() const {
#if defined(JSON_NO_INT64)
  return asInt();
#else
  return asInt64();
#endif
}

LargestUInt Value::asLargestUInt() const {
#if defined(JSON_NO_INT64)
  return asUInt();
#else
  return asUInt64();
#endif
}

double Value::asDouble() const {
  switch (type_) {
  case intValue:
    return static_cast<double>(value_.int_);
  case uintValue:
#if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
    return static_cast<double>(value_.uint_);
#else  // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
    return integerToDouble(value_.uint_);
#endif // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
  case realValue:
    return value_.real_;
  case nullValue:
    return 0.0;
  case booleanValue:
    return value_.bool_ ? 1.0 : 0.0;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to double.");
}

float Value::asFloat() const {
  switch (type_) {
  case intValue:
    return static_cast<float>(value_.int_);
  case uintValue:
#if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
    return static_cast<float>(value_.uint_);
#else  // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
    return integerToDouble(value_.uint_);
#endif // if !defined(JSON_USE_INT64_DOUBLE_CONVERSION)
  case realValue:
    return static_cast<float>(value_.real_);
  case nullValue:
    return 0.0;
  case booleanValue:
    return value_.bool_ ? 1.0f : 0.0f;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to float.");
}

bool Value::asBool() const {
  switch (type_) {
  case booleanValue:
    return value_.bool_;
  case nullValue:
    return false;
  case intValue:
    return value_.int_ ? true : false;
  case uintValue:
    return value_.uint_ ? true : false;
  case realValue:
    return value_.real_ ? true : false;
  default:
    break;
  }
  JSON_FAIL_MESSAGE("Value is not convertible to bool.");
}

bool Value::isConvertibleTo(ValueType other) const {
  switch (other) {
  case nullValue:
    return (isNumeric() && asDouble() == 0.0) ||
           (type_ == booleanValue && value_.bool_ == false) ||
           (type_ == stringValue && asString() == "") ||
           (type_ == arrayValue && value_.map_->size() == 0) ||
           (type_ == objectValue && value_.map_->size() == 0) ||
           type_ == nullValue;
  case intValue:
    return isInt() ||
           (type_ == realValue && InRange(value_.real_, minInt, maxInt)) ||
           type_ == booleanValue || type_ == nullValue;
  case uintValue:
    return isUInt() ||
           (type_ == realValue && InRange(value_.real_, 0, maxUInt)) ||
           type_ == booleanValue || type_ == nullValue;
  case realValue:
    return isNumeric() || type_ == booleanValue || type_ == nullValue;
  case booleanValue:
    return isNumeric() || type_ == booleanValue || type_ == nullValue;
  case stringValue:
    return isNumeric() || type_ == booleanValue || type_ == stringValue ||
           type_ == nullValue;
  case arrayValue:
    return type_ == arrayValue || type_ == nullValue;
  case objectValue:
    return type_ == objectValue || type_ == nullValue;
  }
  JSON_ASSERT_UNREACHABLE;
  return false;
}

/// Number of values in array or object
ArrayIndex Value::size() const {
  switch (type_) {
  case nullValue:
  case intValue:
  case uintValue:
  case realValue:
  case booleanValue:
  case stringValue:
    return 0;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue: // size of the array is highest index + 1
    if (!value_.map_->empty()) {
      ObjectValues::const_iterator itLast = value_.map_->end();
      --itLast;
      return (*itLast).first.index() + 1;
    }
    return 0;
  case objectValue:
    return ArrayIndex(value_.map_->size());
#else
  case arrayValue:
    return Int(value_.array_->size());
  case objectValue:
    return Int(value_.map_->size());
#endif
  }
  JSON_ASSERT_UNREACHABLE;
  return 0; // unreachable;
}

bool Value::empty() const {
  if (isNull() || isArray() || isObject())
    return size() == 0u;
  else
    return false;
}

bool Value::operator!() const { return isNull(); }

void Value::clear() {
  JSON_ASSERT_MESSAGE(type_ == nullValue || type_ == arrayValue ||
                          type_ == objectValue,
                      "in Json::Value::clear(): requires complex value");
  start_ = 0;
  limit_ = 0;
  switch (type_) {
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
  case objectValue:
    value_.map_->clear();
    break;
#else
  case arrayValue:
    value_.array_->clear();
    break;
  case objectValue:
    value_.map_->clear();
    break;
#endif
  default:
    break;
  }
}

void Value::resize(ArrayIndex newSize) {
  JSON_ASSERT_MESSAGE(type_ == nullValue || type_ == arrayValue,
                      "in Json::Value::resize(): requires arrayValue");
  if (type_ == nullValue)
    *this = Value(arrayValue);
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  ArrayIndex oldSize = size();
  if (newSize == 0)
    clear();
  else if (newSize > oldSize)
    (*this)[newSize - 1];
  else {
    for (ArrayIndex index = newSize; index < oldSize; ++index) {
      value_.map_->erase(index);
    }
    assert(size() == newSize);
  }
#else
  value_.array_->resize(newSize);
#endif
}

Value &Value::operator[](ArrayIndex index) {
  JSON_ASSERT_MESSAGE(
      type_ == nullValue || type_ == arrayValue,
      "in Json::Value::operator[](ArrayIndex): requires arrayValue");
  if (type_ == nullValue)
    *this = Value(arrayValue);
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  CZString key(index);
  ObjectValues::iterator it = value_.map_->lower_bound(key);
  if (it != value_.map_->end() && (*it).first == key)
    return (*it).second;

  ObjectValues::value_type defaultValue(key, null);
  it = value_.map_->insert(it, defaultValue);
  return (*it).second;
#else
  return value_.array_->resolveReference(index);
#endif
}

Value &Value::operator[](int index) {
  JSON_ASSERT_MESSAGE(
      index >= 0,
      "in Json::Value::operator[](int index): index cannot be negative");
  return (*this)[ArrayIndex(index)];
}

const Value &Value::operator[](ArrayIndex index) const {
  JSON_ASSERT_MESSAGE(
      type_ == nullValue || type_ == arrayValue,
      "in Json::Value::operator[](ArrayIndex)const: requires arrayValue");
  if (type_ == nullValue)
    return null;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  CZString key(index);
  ObjectValues::const_iterator it = value_.map_->find(key);
  if (it == value_.map_->end())
    return null;
  return (*it).second;
#else
  Value *value = value_.array_->find(index);
  return value ? *value : null;
#endif
}

const Value &Value::operator[](int index) const {
  JSON_ASSERT_MESSAGE(
      index >= 0,
      "in Json::Value::operator[](int index) const: index cannot be negative");
  return (*this)[ArrayIndex(index)];
}

Value &Value::operator[](const char *key) {
  return resolveReference(key, false);
}

Value &Value::resolveReference(const char *key, bool isStatic) {
  JSON_ASSERT_MESSAGE(
      type_ == nullValue || type_ == objectValue,
      "in Json::Value::resolveReference(): requires objectValue");
  if (type_ == nullValue)
    *this = Value(objectValue);
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  CZString actualKey(
      key, isStatic ? CZString::noDuplication : CZString::duplicateOnCopy);
  ObjectValues::iterator it = value_.map_->lower_bound(actualKey);
  if (it != value_.map_->end() && (*it).first == actualKey)
    return (*it).second;

  ObjectValues::value_type defaultValue(actualKey, null);
  it = value_.map_->insert(it, defaultValue);
  Value &value = (*it).second;
  return value;
#else
  return value_.map_->resolveReference(key, isStatic);
#endif
}

Value Value::get(ArrayIndex index, const Value &defaultValue) const {
  const Value *value = &((*this)[index]);
  return value == &null ? defaultValue : *value;
}

bool Value::isValidIndex(ArrayIndex index) const { return index < size(); }

const Value &Value::operator[](const char *key) const {
  JSON_ASSERT_MESSAGE(
      type_ == nullValue || type_ == objectValue,
      "in Json::Value::operator[](char const*)const: requires objectValue");
  if (type_ == nullValue)
    return null;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  CZString actualKey(key, CZString::noDuplication);
  ObjectValues::const_iterator it = value_.map_->find(actualKey);
  if (it == value_.map_->end())
    return null;
  return (*it).second;
#else
  const Value *value = value_.map_->find(key);
  return value ? *value : null;
#endif
}

Value &Value::operator[](const std::string &key) {
  return (*this)[key.c_str()];
}

const Value &Value::operator[](const std::string &key) const {
  return (*this)[key.c_str()];
}

Value &Value::operator[](const StaticString &key) {
  return resolveReference(key, true);
}

#ifdef JSON_USE_CPPTL
Value &Value::operator[](const CppTL::ConstString &key) {
  return (*this)[key.c_str()];
}

const Value &Value::operator[](const CppTL::ConstString &key) const {
  return (*this)[key.c_str()];
}
#endif

Value &Value::append(const Value &value) { return (*this)[size()] = value; }

Value Value::get(const char *key, const Value &defaultValue) const {
  const Value *value = &((*this)[key]);
  return value == &null ? defaultValue : *value;
}

Value Value::get(const std::string &key, const Value &defaultValue) const {
  return get(key.c_str(), defaultValue);
}

Value Value::removeMember(const char *key) {
  JSON_ASSERT_MESSAGE(type_ == nullValue || type_ == objectValue,
                      "in Json::Value::removeMember(): requires objectValue");
  if (type_ == nullValue)
    return null;
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  CZString actualKey(key, CZString::noDuplication);
  ObjectValues::iterator it = value_.map_->find(actualKey);
  if (it == value_.map_->end())
    return null;
  Value old(it->second);
  value_.map_->erase(it);
  return old;
#else
  Value *value = value_.map_->find(key);
  if (value) {
    Value old(*value);
    value_.map_.remove(key);
    return old;
  } else {
    return null;
  }
#endif
}

Value Value::removeMember(const std::string &key) {
  return removeMember(key.c_str());
}

#ifdef JSON_USE_CPPTL
Value Value::get(const CppTL::ConstString &key,
                 const Value &defaultValue) const {
  return get(key.c_str(), defaultValue);
}
#endif

bool Value::isMember(const char *key) const {
  const Value *value = &((*this)[key]);
  return value != &null;
}

bool Value::isMember(const std::string &key) const {
  return isMember(key.c_str());
}

#ifdef JSON_USE_CPPTL
bool Value::isMember(const CppTL::ConstString &key) const {
  return isMember(key.c_str());
}
#endif

Value::Members Value::getMemberNames() const {
  JSON_ASSERT_MESSAGE(
      type_ == nullValue || type_ == objectValue,
      "in Json::Value::getMemberNames(), value must be objectValue");
  if (type_ == nullValue)
    return Value::Members();
  Members members;
  members.reserve(value_.map_->size());
#ifndef JSON_VALUE_USE_INTERNAL_MAP
  ObjectValues::const_iterator it = value_.map_->begin();
  ObjectValues::const_iterator itEnd = value_.map_->end();
  for (; it != itEnd; ++it)
    members.push_back(std::string((*it).first.c_str()));
#else
  ValueInternalMap::IteratorState it;
  ValueInternalMap::IteratorState itEnd;
  value_.map_->makeBeginIterator(it);
  value_.map_->makeEndIterator(itEnd);
  for (; !ValueInternalMap::equals(it, itEnd); ValueInternalMap::increment(it))
    members.push_back(std::string(ValueInternalMap::key(it)));
#endif
  return members;
}
//
//# ifdef JSON_USE_CPPTL
// EnumMemberNames
// Value::enumMemberNames() const
//{
//   if ( type_ == objectValue )
//   {
//      return CppTL::Enum::any(  CppTL::Enum::transform(
//         CppTL::Enum::keys( *(value_.map_), CppTL::Type<const CZString &>() ),
//         MemberNamesTransform() ) );
//   }
//   return EnumMemberNames();
//}
//
//
// EnumValues
// Value::enumValues() const
//{
//   if ( type_ == objectValue  ||  type_ == arrayValue )
//      return CppTL::Enum::anyValues( *(value_.map_),
//                                     CppTL::Type<const Value &>() );
//   return EnumValues();
//}
//
//# endif

static bool IsIntegral(double d) {
  double integral_part;
  return modf(d, &integral_part) == 0.0;
}

bool Value::isNull() const { return type_ == nullValue; }

bool Value::isBool() const { return type_ == booleanValue; }

bool Value::isInt() const {
  switch (type_) {
  case intValue:
    return value_.int_ >= minInt && value_.int_ <= maxInt;
  case uintValue:
    return value_.uint_ <= UInt(maxInt);
  case realValue:
    return value_.real_ >= minInt && value_.real_ <= maxInt &&
           IsIntegral(value_.real_);
  default:
    break;
  }
  return false;
}

bool Value::isUInt() const {
  switch (type_) {
  case intValue:
    return value_.int_ >= 0 && LargestUInt(value_.int_) <= LargestUInt(maxUInt);
  case uintValue:
    return value_.uint_ <= maxUInt;
  case realValue:
    return value_.real_ >= 0 && value_.real_ <= maxUInt &&
           IsIntegral(value_.real_);
  default:
    break;
  }
  return false;
}

bool Value::isInt64() const {
#if defined(JSON_HAS_INT64)
  switch (type_) {
  case intValue:
    return true;
  case uintValue:
    return value_.uint_ <= UInt64(maxInt64);
  case realValue:
    // Note that maxInt64 (= 2^63 - 1) is not exactly representable as a
    // double, so double(maxInt64) will be rounded up to 2^63. Therefore we
    // require the value to be strictly less than the limit.
    return value_.real_ >= double(minInt64) &&
           value_.real_ < double(maxInt64) && IsIntegral(value_.real_);
  default:
    break;
  }
#endif // JSON_HAS_INT64
  return false;
}

bool Value::isUInt64() const {
#if defined(JSON_HAS_INT64)
  switch (type_) {
  case intValue:
    return value_.int_ >= 0;
  case uintValue:
    return true;
  case realValue:
    // Note that maxUInt64 (= 2^64 - 1) is not exactly representable as a
    // double, so double(maxUInt64) will be rounded up to 2^64. Therefore we
    // require the value to be strictly less than the limit.
    return value_.real_ >= 0 && value_.real_ < maxUInt64AsDouble &&
           IsIntegral(value_.real_);
  default:
    break;
  }
#endif // JSON_HAS_INT64
  return false;
}

bool Value::isIntegral() const {
#if defined(JSON_HAS_INT64)
  return isInt64() || isUInt64();
#else
  return isInt() || isUInt();
#endif
}

bool Value::isDouble() const { return type_ == realValue || isIntegral(); }

bool Value::isNumeric() const { return isIntegral() || isDouble(); }

bool Value::isString() const { return type_ == stringValue; }

bool Value::isArray() const { return type_ == arrayValue; }

bool Value::isObject() const { return type_ == objectValue; }

void Value::setComment(const char *comment, CommentPlacement placement) {
  if (!comments_)
    comments_ = new CommentInfo[numberOfCommentPlacement];
  comments_[placement].setComment(comment);
}

void Value::setComment(const std::string &comment, CommentPlacement placement) {
  setComment(comment.c_str(), placement);
}

bool Value::hasComment(CommentPlacement placement) const {
  return comments_ != 0 && comments_[placement].comment_ != 0;
}

std::string Value::getComment(CommentPlacement placement) const {
  if (hasComment(placement))
    return comments_[placement].comment_;
  return "";
}

void Value::setOffsetStart(size_t start) { start_ = start; }

void Value::setOffsetLimit(size_t limit) { limit_ = limit; }

size_t Value::getOffsetStart() const { return start_; }

size_t Value::getOffsetLimit() const { return limit_; }

std::string Value::toStyledString() const {
  StyledWriter writer;
  return writer.write(*this);
}

Value::const_iterator Value::begin() const {
  switch (type_) {
#ifdef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
    if (value_.array_) {
      ValueInternalArray::IteratorState it;
      value_.array_->makeBeginIterator(it);
      return const_iterator(it);
    }
    break;
  case objectValue:
    if (value_.map_) {
      ValueInternalMap::IteratorState it;
      value_.map_->makeBeginIterator(it);
      return const_iterator(it);
    }
    break;
#else
  case arrayValue:
  case objectValue:
    if (value_.map_)
      return const_iterator(value_.map_->begin());
    break;
#endif
  default:
    break;
  }
  return const_iterator();
}

Value::const_iterator Value::end() const {
  switch (type_) {
#ifdef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
    if (value_.array_) {
      ValueInternalArray::IteratorState it;
      value_.array_->makeEndIterator(it);
      return const_iterator(it);
    }
    break;
  case objectValue:
    if (value_.map_) {
      ValueInternalMap::IteratorState it;
      value_.map_->makeEndIterator(it);
      return const_iterator(it);
    }
    break;
#else
  case arrayValue:
  case objectValue:
    if (value_.map_)
      return const_iterator(value_.map_->end());
    break;
#endif
  default:
    break;
  }
  return const_iterator();
}

Value::iterator Value::begin() {
  switch (type_) {
#ifdef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
    if (value_.array_) {
      ValueInternalArray::IteratorState it;
      value_.array_->makeBeginIterator(it);
      return iterator(it);
    }
    break;
  case objectValue:
    if (value_.map_) {
      ValueInternalMap::IteratorState it;
      value_.map_->makeBeginIterator(it);
      return iterator(it);
    }
    break;
#else
  case arrayValue:
  case objectValue:
    if (value_.map_)
      return iterator(value_.map_->begin());
    break;
#endif
  default:
    break;
  }
  return iterator();
}

Value::iterator Value::end() {
  switch (type_) {
#ifdef JSON_VALUE_USE_INTERNAL_MAP
  case arrayValue:
    if (value_.array_) {
      ValueInternalArray::IteratorState it;
      value_.array_->makeEndIterator(it);
      return iterator(it);
    }
    break;
  case objectValue:
    if (value_.map_) {
      ValueInternalMap::IteratorState it;
      value_.map_->makeEndIterator(it);
      return iterator(it);
    }
    break;
#else
  case arrayValue:
  case objectValue:
    if (value_.map_)
      return iterator(value_.map_->end());
    break;
#endif
  default:
    break;
  }
  return iterator();
}

// class PathArgument
// //////////////////////////////////////////////////////////////////

PathArgument::PathArgument() : key_(), index_(), kind_(kindNone) {}

PathArgument::PathArgument(ArrayIndex index)
    : key_(), index_(index), kind_(kindIndex) {}

PathArgument::PathArgument(const char *key)
    : key_(key), index_(), kind_(kindKey) {}

PathArgument::PathArgument(const std::string &key)
    : key_(key.c_str()), index_(), kind_(kindKey) {}

// class Path
// //////////////////////////////////////////////////////////////////

Path::Path(const std::string &path,
           const PathArgument &a1,
           const PathArgument &a2,
           const PathArgument &a3,
           const PathArgument &a4,
           const PathArgument &a5) {
  InArgs in;
  in.push_back(&a1);
  in.push_back(&a2);
  in.push_back(&a3);
  in.push_back(&a4);
  in.push_back(&a5);
  makePath(path, in);
}

void Path::makePath(const std::string &path, const InArgs &in) {
  const char *current = path.c_str();
  const char *end = current + path.length();
  InArgs::const_iterator itInArg = in.begin();
  while (current != end) {
    if (*current == '[') {
      ++current;
      if (*current == '%')
        addPathInArg(path, in, itInArg, PathArgument::kindIndex);
      else {
        ArrayIndex index = 0;
        for (; current != end && *current >= '0' && *current <= '9'; ++current)
          index = index * 10 + ArrayIndex(*current - '0');
        args_.push_back(index);
      }
      if (current == end || *current++ != ']')
        invalidPath(path, int(current - path.c_str()));
    } else if (*current == '%') {
      addPathInArg(path, in, itInArg, PathArgument::kindKey);
      ++current;
    } else if (*current == '.') {
      ++current;
    } else {
      const char *beginName = current;
      while (current != end && !strchr("[.", *current))
        ++current;
      args_.push_back(std::string(beginName, current));
    }
  }
}

void Path::addPathInArg(const std::string & /*path*/,
                        const InArgs &in,
                        InArgs::const_iterator &itInArg,
                        PathArgument::Kind kind) {
  if (itInArg == in.end()) {
    // Error: missing argument %d
  } else if ((*itInArg)->kind_ != kind) {
    // Error: bad argument type
  } else {
    args_.push_back(**itInArg);
  }
}

void Path::invalidPath(const std::string & /*path*/, int /*location*/) {
  // Error: invalid path.
}

const Value &Path::resolve(const Value &root) const {
  const Value *node = &root;
  for (Args::const_iterator it = args_.begin(); it != args_.end(); ++it) {
    const PathArgument &arg = *it;
    if (arg.kind_ == PathArgument::kindIndex) {
      if (!node->isArray() || !node->isValidIndex(arg.index_)) {
        // Error: unable to resolve path (array value expected at position...
      }
      node = &((*node)[arg.index_]);
    } else if (arg.kind_ == PathArgument::kindKey) {
      if (!node->isObject()) {
        // Error: unable to resolve path (object value expected at position...)
      }
      node = &((*node)[arg.key_]);
      if (node == &Value::null) {
        // Error: unable to resolve path (object has no member named '' at
        // position...)
      }
    }
  }
  return *node;
}

Value Path::resolve(const Value &root, const Value &defaultValue) const {
  const Value *node = &root;
  for (Args::const_iterator it = args_.begin(); it != args_.end(); ++it) {
    const PathArgument &arg = *it;
    if (arg.kind_ == PathArgument::kindIndex) {
      if (!node->isArray() || !node->isValidIndex(arg.index_))
        return defaultValue;
      node = &((*node)[arg.index_]);
    } else if (arg.kind_ == PathArgument::kindKey) {
      if (!node->isObject())
        return defaultValue;
      node = &((*node)[arg.key_]);
      if (node == &Value::null)
        return defaultValue;
    }
  }
  return *node;
}

Value &Path::make(Value &root) const {
  Value *node = &root;
  for (Args::const_iterator it = args_.begin(); it != args_.end(); ++it) {
    const PathArgument &arg = *it;
    if (arg.kind_ == PathArgument::kindIndex) {
      if (!node->isArray()) {
        // Error: node is not an array at position ...
      }
      node = &((*node)[arg.index_]);
    } else if (arg.kind_ == PathArgument::kindKey) {
      if (!node->isObject()) {
        // Error: node is not an object at position...
      }
      node = &((*node)[arg.key_]);
    }
  }
  return *node;
}

} // namespace Json
// vim: et ts=2 sts=2 sw=2 tw=0

/***************************************************
 * external/jsoncpp/src/lib_json/json_writer.cpp
 ***************************************************/

// Copyright 2011 Baptiste Lepilleur
// Distributed under MIT license, or public domain if desired and
// recognized in your jurisdiction.
// See file LICENSE for detail or copy at http://jsoncpp.sourceforge.net/LICENSE

#if !defined(JSON_IS_AMALGAMATION)
#include <json/writer.h>
#include "json_tool.h"
#endif // if !defined(JSON_IS_AMALGAMATION)
#include <utility>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <iomanip>

#if defined(_MSC_VER) && _MSC_VER >= 1400 // VC++ 8.0
// Disable warning about strdup being deprecated.
#pragma warning(disable : 4996)
#endif

namespace Json {

static bool containsControlCharacter(const char *str) {
  while (*str) {
    if (isControlCharacter(*(str++)))
      return true;
  }
  return false;
}

std::string valueToString(LargestInt value) {
  UIntToStringBuffer buffer;
  char *current = buffer + sizeof(buffer);
  bool isNegative = value < 0;
  if (isNegative)
    value = -value;
  uintToString(LargestUInt(value), current);
  if (isNegative)
    *--current = '-';
  assert(current >= buffer);
  return current;
}

std::string valueToString(LargestUInt value) {
  UIntToStringBuffer buffer;
  char *current = buffer + sizeof(buffer);
  uintToString(value, current);
  assert(current >= buffer);
  return current;
}

#if defined(JSON_HAS_INT64)

std::string valueToString(Int value) {
  return valueToString(LargestInt(value));
}

std::string valueToString(UInt value) {
  return valueToString(LargestUInt(value));
}

#endif // # if defined(JSON_HAS_INT64)

std::string valueToString(double value) {
  // Allocate a buffer that is more than large enough to store the 16 digits of
  // precision requested below.
  char buffer[32];

// Print into the buffer. We need not request the alternative representation
// that always has a decimal point because JSON doesn't distingish the
// concepts of reals and integers.
#if defined(_MSC_VER) && defined(__STDC_SECURE_LIB__) // Use secure version with
                                                      // visual studio 2005 to
                                                      // avoid warning.
  #if defined(WINCE)
  _snprintf(buffer, sizeof(buffer), "%.16g", value);
  #else
  sprintf_s(buffer, sizeof(buffer), "%.16g", value);
  #endif
#else
  snprintf(buffer, sizeof(buffer), "%.16g", value);
#endif
  fixNumericLocale(buffer, buffer + strlen(buffer));
  return buffer;
}

std::string valueToString(bool value) { return value ? "true" : "false"; }

std::string valueToQuotedString(const char *value) {
  if (value == NULL)
    return "";
  // Not sure how to handle unicode...
  if (strpbrk(value, "\"\\\b\f\n\r\t") == NULL &&
      !containsControlCharacter(value))
    return std::string("\"") + value + "\"";
  // We have to walk value and escape any special characters.
  // Appending to std::string is not efficient, but this should be rare.
  // (Note: forward slashes are *not* rare, but I am not escaping them.)
  std::string::size_type maxsize =
      strlen(value) * 2 + 3; // allescaped+quotes+NULL
  std::string result;
  result.reserve(maxsize); // to avoid lots of mallocs
  result += "\"";
  for (const char *c = value; *c != 0; ++c) {
    switch (*c) {
    case '\"':
      result += "\\\"";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    // case '/':
    // Even though \/ is considered a legal escape in JSON, a bare
    // slash is also legal, so I see no reason to escape it.
    // (I hope I am not misunderstanding something.
    // blep notes: actually escaping \/ may be useful in javascript to avoid </
    // sequence.
    // Should add a flag to allow this compatibility mode and prevent this
    // sequence from occurring.
    default:
      if (isControlCharacter(*c)) {
        std::ostringstream oss;
        oss << "\\u" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << static_cast<int>(*c);
        result += oss.str();
      } else {
        result += *c;
      }
      break;
    }
  }
  result += "\"";
  return result;
}

// Class Writer
// //////////////////////////////////////////////////////////////////
Writer::~Writer() {}

// Class FastWriter
// //////////////////////////////////////////////////////////////////

FastWriter::FastWriter()
    : yamlCompatiblityEnabled_(false), dropNullPlaceholders_(false) {}

void FastWriter::enableYAMLCompatibility() { yamlCompatiblityEnabled_ = true; }

void FastWriter::dropNullPlaceholders() { dropNullPlaceholders_ = true; }

std::string FastWriter::write(const Value &root) {
  document_ = "";
  writeValue(root);
  document_ += "\n";
  return document_;
}

void FastWriter::writeValue(const Value &value) {
  switch (value.type()) {
  case nullValue:
    if (!dropNullPlaceholders_)
      document_ += "null";
    break;
  case intValue:
    document_ += valueToString(value.asLargestInt());
    break;
  case uintValue:
    document_ += valueToString(value.asLargestUInt());
    break;
  case realValue:
    document_ += valueToString(value.asDouble());
    break;
  case stringValue:
    document_ += valueToQuotedString(value.asCString());
    break;
  case booleanValue:
    document_ += valueToString(value.asBool());
    break;
  case arrayValue: {
    document_ += "[";
    int size = value.size();
    for (int index = 0; index < size; ++index) {
      if (index > 0)
        document_ += ",";
      writeValue(value[index]);
    }
    document_ += "]";
  } break;
  case objectValue: {
    Value::Members members(value.getMemberNames());
    document_ += "{";
    for (Value::Members::iterator it = members.begin(); it != members.end();
         ++it) {
      const std::string &name = *it;
      if (it != members.begin())
        document_ += ",";
      document_ += valueToQuotedString(name.c_str());
      document_ += yamlCompatiblityEnabled_ ? ": " : ":";
      writeValue(value[name]);
    }
    document_ += "}";
  } break;
  }
}

// Class StyledWriter
// //////////////////////////////////////////////////////////////////

StyledWriter::StyledWriter()
    : rightMargin_(74), indentSize_(3), addChildValues_() {}

std::string StyledWriter::write(const Value &root) {
  document_ = "";
  addChildValues_ = false;
  indentString_ = "";
  writeCommentBeforeValue(root);
  writeValue(root);
  writeCommentAfterValueOnSameLine(root);
  document_ += "\n";
  return document_;
}

void StyledWriter::writeValue(const Value &value) {
  switch (value.type()) {
  case nullValue:
    pushValue("null");
    break;
  case intValue:
    pushValue(valueToString(value.asLargestInt()));
    break;
  case uintValue:
    pushValue(valueToString(value.asLargestUInt()));
    break;
  case realValue:
    pushValue(valueToString(value.asDouble()));
    break;
  case stringValue:
    pushValue(valueToQuotedString(value.asCString()));
    break;
  case booleanValue:
    pushValue(valueToString(value.asBool()));
    break;
  case arrayValue:
    writeArrayValue(value);
    break;
  case objectValue: {
    Value::Members members(value.getMemberNames());
    if (members.empty())
      pushValue("{}");
    else {
      writeWithIndent("{");
      indent();
      Value::Members::iterator it = members.begin();
      for (;;) {
        const std::string &name = *it;
        const Value &childValue = value[name];
        writeCommentBeforeValue(childValue);
        writeWithIndent(valueToQuotedString(name.c_str()));
        document_ += " : ";
        writeValue(childValue);
        if (++it == members.end()) {
          writeCommentAfterValueOnSameLine(childValue);
          break;
        }
        document_ += ",";
        writeCommentAfterValueOnSameLine(childValue);
      }
      unindent();
      writeWithIndent("}");
    }
  } break;
  }
}

void StyledWriter::writeArrayValue(const Value &value) {
  unsigned size = value.size();
  if (size == 0)
    pushValue("[]");
  else {
    bool isArrayMultiLine = isMultineArray(value);
    if (isArrayMultiLine) {
      writeWithIndent("[");
      indent();
      bool hasChildValue = !childValues_.empty();
      unsigned index = 0;
      for (;;) {
        const Value &childValue = value[index];
        writeCommentBeforeValue(childValue);
        if (hasChildValue)
          writeWithIndent(childValues_[index]);
        else {
          writeIndent();
          writeValue(childValue);
        }
        if (++index == size) {
          writeCommentAfterValueOnSameLine(childValue);
          break;
        }
        document_ += ",";
        writeCommentAfterValueOnSameLine(childValue);
      }
      unindent();
      writeWithIndent("]");
    } else // output on a single line
    {
      assert(childValues_.size() == size);
      document_ += "[ ";
      for (unsigned index = 0; index < size; ++index) {
        if (index > 0)
          document_ += ", ";
        document_ += childValues_[index];
      }
      document_ += " ]";
    }
  }
}

bool StyledWriter::isMultineArray(const Value &value) {
  int size = value.size();
  bool isMultiLine = size * 3 >= rightMargin_;
  childValues_.clear();
  for (int index = 0; index < size && !isMultiLine; ++index) {
    const Value &childValue = value[index];
    isMultiLine =
        isMultiLine || ((childValue.isArray() || childValue.isObject()) &&
                        childValue.size() > 0);
  }
  if (!isMultiLine) // check if line length > max line length
  {
    childValues_.reserve(size);
    addChildValues_ = true;
    int lineLength = 4 + (size - 1) * 2; // '[ ' + ', '*n + ' ]'
    for (int index = 0; index < size; ++index) {
      writeValue(value[index]);
      lineLength += int(childValues_[index].length());
    }
    addChildValues_ = false;
    isMultiLine = isMultiLine || lineLength >= rightMargin_;
  }
  return isMultiLine;
}

void StyledWriter::pushValue(const std::string &value) {
  if (addChildValues_)
    childValues_.push_back(value);
  else
    document_ += value;
}

void StyledWriter::writeIndent() {
  if (!document_.empty()) {
    char last = document_[document_.length() - 1];
    if (last == ' ') // already indented
      return;
    if (last != '\n') // Comments may add new-line
      document_ += '\n';
  }
  document_ += indentString_;
}

void StyledWriter::writeWithIndent(const std::string &value) {
  writeIndent();
  document_ += value;
}

void StyledWriter::indent() { indentString_ += std::string(indentSize_, ' '); }

void StyledWriter::unindent() {
  assert(int(indentString_.size()) >= indentSize_);
  indentString_.resize(indentString_.size() - indentSize_);
}

void StyledWriter::writeCommentBeforeValue(const Value &root) {
  if (!root.hasComment(commentBefore))
    return;

  document_ += "\n";
  writeIndent();
  std::string normalizedComment = normalizeEOL(root.getComment(commentBefore));
  std::string::const_iterator iter = normalizedComment.begin();
  while (iter != normalizedComment.end()) {
    document_ += *iter;
    if (*iter == '\n' && *(iter + 1) == '/')
      writeIndent();
    ++iter;
  }

  // Comments are stripped of newlines, so add one here
  document_ += "\n";
}

void StyledWriter::writeCommentAfterValueOnSameLine(const Value &root) {
  if (root.hasComment(commentAfterOnSameLine))
    document_ += " " + normalizeEOL(root.getComment(commentAfterOnSameLine));

  if (root.hasComment(commentAfter)) {
    document_ += "\n";
    document_ += normalizeEOL(root.getComment(commentAfter));
    document_ += "\n";
  }
}

bool StyledWriter::hasCommentForValue(const Value &value) {
  return value.hasComment(commentBefore) ||
         value.hasComment(commentAfterOnSameLine) ||
         value.hasComment(commentAfter);
}

std::string StyledWriter::normalizeEOL(const std::string &text) {
  std::string normalized;
  normalized.reserve(text.length());
  const char *begin = text.c_str();
  const char *end = begin + text.length();
  const char *current = begin;
  while (current != end) {
    char c = *current++;
    if (c == '\r') // mac or dos EOL
    {
      if (*current == '\n') // convert dos EOL
        ++current;
      normalized += '\n';
    } else // handle unix EOL & other char
      normalized += c;
  }
  return normalized;
}

// Class StyledStreamWriter
// //////////////////////////////////////////////////////////////////

StyledStreamWriter::StyledStreamWriter(std::string indentation)
    : document_(NULL), rightMargin_(74), indentation_(indentation),
      addChildValues_() {}

void StyledStreamWriter::write(std::ostream &out, const Value &root) {
  document_ = &out;
  addChildValues_ = false;
  indentString_ = "";
  writeCommentBeforeValue(root);
  writeValue(root);
  writeCommentAfterValueOnSameLine(root);
  *document_ << "\n";
  document_ = NULL; // Forget the stream, for safety.
}

void StyledStreamWriter::writeValue(const Value &value) {
  switch (value.type()) {
  case nullValue:
    pushValue("null");
    break;
  case intValue:
    pushValue(valueToString(value.asLargestInt()));
    break;
  case uintValue:
    pushValue(valueToString(value.asLargestUInt()));
    break;
  case realValue:
    pushValue(valueToString(value.asDouble()));
    break;
  case stringValue:
    pushValue(valueToQuotedString(value.asCString()));
    break;
  case booleanValue:
    pushValue(valueToString(value.asBool()));
    break;
  case arrayValue:
    writeArrayValue(value);
    break;
  case objectValue: {
    Value::Members members(value.getMemberNames());
    if (members.empty())
      pushValue("{}");
    else {
      writeWithIndent("{");
      indent();
      Value::Members::iterator it = members.begin();
      for (;;) {
        const std::string &name = *it;
        const Value &childValue = value[name];
        writeCommentBeforeValue(childValue);
        writeWithIndent(valueToQuotedString(name.c_str()));
        *document_ << " : ";
        writeValue(childValue);
        if (++it == members.end()) {
          writeCommentAfterValueOnSameLine(childValue);
          break;
        }
        *document_ << ",";
        writeCommentAfterValueOnSameLine(childValue);
      }
      unindent();
      writeWithIndent("}");
    }
  } break;
  }
}

void StyledStreamWriter::writeArrayValue(const Value &value) {
  unsigned size = value.size();
  if (size == 0)
    pushValue("[]");
  else {
    bool isArrayMultiLine = isMultineArray(value);
    if (isArrayMultiLine) {
      writeWithIndent("[");
      indent();
      bool hasChildValue = !childValues_.empty();
      unsigned index = 0;
      for (;;) {
        const Value &childValue = value[index];
        writeCommentBeforeValue(childValue);
        if (hasChildValue)
          writeWithIndent(childValues_[index]);
        else {
          writeIndent();
          writeValue(childValue);
        }
        if (++index == size) {
          writeCommentAfterValueOnSameLine(childValue);
          break;
        }
        *document_ << ",";
        writeCommentAfterValueOnSameLine(childValue);
      }
      unindent();
      writeWithIndent("]");
    } else // output on a single line
    {
      assert(childValues_.size() == size);
      *document_ << "[ ";
      for (unsigned index = 0; index < size; ++index) {
        if (index > 0)
          *document_ << ", ";
        *document_ << childValues_[index];
      }
      *document_ << " ]";
    }
  }
}

bool StyledStreamWriter::isMultineArray(const Value &value) {
  int size = value.size();
  bool isMultiLine = size * 3 >= rightMargin_;
  childValues_.clear();
  for (int index = 0; index < size && !isMultiLine; ++index) {
    const Value &childValue = value[index];
    isMultiLine =
        isMultiLine || ((childValue.isArray() || childValue.isObject()) &&
                        childValue.size() > 0);
  }
  if (!isMultiLine) // check if line length > max line length
  {
    childValues_.reserve(size);
    addChildValues_ = true;
    int lineLength = 4 + (size - 1) * 2; // '[ ' + ', '*n + ' ]'
    for (int index = 0; index < size; ++index) {
      writeValue(value[index]);
      lineLength += int(childValues_[index].length());
    }
    addChildValues_ = false;
    isMultiLine = isMultiLine || lineLength >= rightMargin_;
  }
  return isMultiLine;
}

void StyledStreamWriter::pushValue(const std::string &value) {
  if (addChildValues_)
    childValues_.push_back(value);
  else
    *document_ << value;
}

void StyledStreamWriter::writeIndent() {
  /*
    Some comments in this method would have been nice. ;-)

   if ( !document_.empty() )
   {
      char last = document_[document_.length()-1];
      if ( last == ' ' )     // already indented
         return;
      if ( last != '\n' )    // Comments may add new-line
         *document_ << '\n';
   }
  */
  *document_ << '\n' << indentString_;
}

void StyledStreamWriter::writeWithIndent(const std::string &value) {
  writeIndent();
  *document_ << value;
}

void StyledStreamWriter::indent() { indentString_ += indentation_; }

void StyledStreamWriter::unindent() {
  assert(indentString_.size() >= indentation_.size());
  indentString_.resize(indentString_.size() - indentation_.size());
}

void StyledStreamWriter::writeCommentBeforeValue(const Value &root) {
  if (!root.hasComment(commentBefore))
    return;
  *document_ << normalizeEOL(root.getComment(commentBefore));
  *document_ << "\n";
}

void StyledStreamWriter::writeCommentAfterValueOnSameLine(const Value &root) {
  if (root.hasComment(commentAfterOnSameLine))
    *document_ << " " + normalizeEOL(root.getComment(commentAfterOnSameLine));

  if (root.hasComment(commentAfter)) {
    *document_ << "\n";
    *document_ << normalizeEOL(root.getComment(commentAfter));
    *document_ << "\n";
  }
}

bool StyledStreamWriter::hasCommentForValue(const Value &value) {
  return value.hasComment(commentBefore) ||
         value.hasComment(commentAfterOnSameLine) ||
         value.hasComment(commentAfter);
}

std::string StyledStreamWriter::normalizeEOL(const std::string &text) {
  std::string normalized;
  normalized.reserve(text.length());
  const char *begin = text.c_str();
  const char *end = begin + text.length();
  const char *current = begin;
  while (current != end) {
    char c = *current++;
    if (c == '\r') // mac or dos EOL
    {
      if (*current == '\n') // convert dos EOL
        ++current;
      normalized += '\n';
    } else // handle unix EOL & other char
      normalized += c;
  }
  return normalized;
}

std::ostream &operator<<(std::ostream &sout, const Value &root) {
  Json::StyledStreamWriter writer;
  writer.write(sout, root);
  return sout;
}

} // namespace Json
// vim: et ts=2 sts=2 sw=2 tw=0


/* libwebsockets code
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 * Distributed under lesser GPL with static linking exception
 */

/***************************************************
 * src/libwebsockets.cpp
 ***************************************************/

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
