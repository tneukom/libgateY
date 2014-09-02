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

#if defined(__GNUC__)
//GCC warns about st = {0}, annoying
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif



namespace gatey {

	struct PerSession {
		long long sessionId;
	};

    struct LibWebsocketsCallbackReasonBoxed {
        libwebsocket_callback_reasons value;
    };

	int callback_impl(libwebsocket_context *context, libwebsocket *wsi, libwebsocket_callback_reasons reason, void *user, void *in, size_t len);
    int callback(libwebsocket_context *context, libwebsocket *wsi, LibWebsocketsCallbackReasonBoxed const& reasonBoxed, void *user, void *in, size_t len);

    static libwebsocket_protocols protocols[] = {
			{ "gatey", &callback_impl, sizeof(PerSession), 0 },
        { 0 }
    };

    static libwebsocket_protocols *webSocketProtocol = &protocols[0];

	//Called in the server thread
    int callback_impl(libwebsocket_context *context, libwebsocket *wsi, libwebsocket_callback_reasons reason, void *user, void *in, size_t len) {
        LibWebsocketsCallbackReasonBoxed reasonBoxed = { reason };
        return callback(context, wsi, reasonBoxed, user, in, len);
    }

    int callback(libwebsocket_context *context, libwebsocket *wsi, LibWebsocketsCallbackReasonBoxed const& reasonBoxed, void *user, void *in, size_t len) {
        WebSocketQueue *self = (WebSocketQueue*)libwebsocket_context_user(context);
        PerSession *perSession = (PerSession*)user;
        libwebsocket_callback_reasons reason = reasonBoxed.value;

		// reason for callback
		switch (reason) {
		case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
			if (self->sessions_.size() > 0) {
				GATEY_LOG("not accepting connection because already connected");
				return -1;
			}
			break;
		}
		case LWS_CALLBACK_ESTABLISHED:
			*perSession = { self->nextUniqueSessionId_ };
			self->nextUniqueSessionId_++;
			self->sessions_.insert(perSession->sessionId);
			if (self->sessions_.size() > 1) {
				GATEY_LOG("connection established but will be canceled" + std::to_string(perSession->sessionId));
				return -1;
			}

			GATEY_LOG("connection established" + std::to_string(perSession->sessionId));
			break;
		case LWS_CALLBACK_RECEIVE: {
			char const* bytes = (char const*)in;
			std::string messageStr(bytes, bytes + len);
			{
				std::lock_guard<std::mutex> guard(self->mutex_);
				self->inMessages_.push_back(std::move(messageStr));
				GATEY_LOG("received message");
			}

			break;
		}
		case LWS_CALLBACK_SERVER_WRITEABLE: {
			//Send messages from the queue
			std::string message;
			{
				std::lock_guard<std::mutex> guard(self->mutex_);
				if (self->outMessages_.empty())
					break;

				message = std::move(self->outMessages_.front());
				self->outMessages_.pop_front();
			}

			std::vector<char> bytes(message.size() + LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING);
			std::copy(message.begin(), message.end(), bytes.begin() + LWS_SEND_BUFFER_PRE_PADDING);

			libwebsocket_write(wsi, (unsigned char*)&bytes[LWS_SEND_BUFFER_PRE_PADDING], message.size(), LWS_WRITE_TEXT);
			self->messageSent_ = true;
			break;
		}
		case LWS_CALLBACK_CLOSED: {
			self->sessions_.erase(perSession->sessionId);
			GATEY_LOG("connection closed" + std::to_string(perSession->sessionId));
			break;
		}

		default: break;
		}

		return 0;
	}

	WebSocketQueue::WebSocketQueue() :
		messageSent_(false),
		nextUniqueSessionId_(0)
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
		//TODO: Check if any out messages, HAAAAAACK
		//std::cout << "outMessages.size()" << outMessages.size() << std::endl;
		std::size_t outMessageCount = outMessages_.size();
		while (!outMessages_.empty()) {
            libwebsocket_callback_on_writable_all_protocol(webSocketProtocol);
			messageSent_ = false;
			libwebsocket_service(context_, 0);
			if (!messageSent_)
				break;
		}

		libwebsocket_service(context_, 10);
	}

	void WebSocketQueue::send(std::string message) {
		std::lock_guard<std::mutex> guard(mutex_);
		outMessages_.push_back(std::move(message));
	}

    std::deque<std::string> WebSocketQueue::receive() {
		std::lock_guard<std::mutex> guard(mutex_);

        std::deque<std::string> result(std::move(inMessages_));
		return result;
	}

}
