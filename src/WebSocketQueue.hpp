/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_WEBSOCKETQUEUE_H
#define GATEY_WEBSOCKETQUEUE_H

#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <set>

struct libwebsocket_context;
struct libwebsocket;

namespace gatey {

    //! So we don't have to include the libwebsockets header
    struct LibWebsocketsCallbackReasonBoxed;

    //! WebSocket server using the libwebsockets library
    struct WebSocketQueue {
	private:
		bool messageSent_;
		long long nextUniqueSessionId_;

        //! List of unique session ids, at the moment only one session at a time is possible
		std::set<long long> sessions_;

		libwebsocket_context *context_;

		mutable std::mutex mutex_;

		//Using list because resizing is costly

        //! Incoming messages, std::string has a nothrow move constructor, therefore
        //! resize should not be a problem
        std::deque<std::string> inMessages_;

        //! Outgoing messages
        std::deque<std::string> outMessages_;

	public:
		//! send, empty, receive can be called from different threads use work only in the one thread
		//! Put message on queue to send
		void send(std::string message);

        //! returns a list of new messages
        std::deque<std::string> receive();

        //! call this to do the actual work: send and receiving messages handling network stuff ...
		void work();

		WebSocketQueue();
		~WebSocketQueue();

        friend int callback(struct libwebsocket_context *context, libwebsocket *wsi,
                            LibWebsocketsCallbackReasonBoxed const& reasonBoxed, void *user, void *in, size_t len);
	};

}

#endif
