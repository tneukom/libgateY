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
    
    typedef long long SessionId;
    
    struct Message {
        std::string content;
        SessionId sessionId;
        
        Message() : sessionId(-1) {
        }
        
        Message(SessionId sessionId, std::string content) :
            sessionId(sessionId),
            content(std::move(content))
        {
        }
        
        Message(Message const& other) = delete;
        Message(Message&& other) = default;
        
        Message& operator=(Message const& other) = delete;
        Message& operator=(Message&& other) = default;
    };

    //! So we don't have to include the libwebsockets header
    struct LibWebsocketsCallbackReasonBoxed;

    //! WebSocket server using the libwebsockets library
    struct WebSocketQueue {
	private:
		bool messageSent_;
		SessionId nextUniqueSessionId_;

        //! List of unique session ids, at the moment only one session at a time is possible
		std::set<SessionId> sessions_;

		libwebsocket_context *context_;

		mutable std::mutex mutex_;

		//Using list because resizing is costly

        //! Incoming messages, std::string has a nothrow move constructor, therefore
        //! resize should not be a problem
        std::deque<Message> inMessages_;

        //! Outgoing messages
        std::deque<Message> outMessages_;

	public:
		//! send, empty, receive can be called from different threads use work only in the one thread
		//! Put message on queue to send
		void send(Message message);

        //! returns a list of new messages
        std::deque<Message> receive();

        //! call this to do the actual work: send and receiving messages handling network stuff ...
		void work();

		WebSocketQueue();
		~WebSocketQueue();

        friend int callback(struct libwebsocket_context *context, libwebsocket *wsi,
                            LibWebsocketsCallbackReasonBoxed const& reasonBoxed,
                            void *user, void *in, size_t len);
	};

}

#endif
