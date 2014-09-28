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
    
    typedef unsigned long long SessionId;
    
    struct WebSocketQueue;
    
    struct OutMessage {
    private:
        std::string content_;
        std::set<SessionId> destionations_; // only defined if Destination == Session
        
        std::vector<char> buffer_;
        std::size_t len_;

		//! = delete
		OutMessage(OutMessage const& other);

		//! = delete
		OutMessage& operator=(OutMessage const& other);
        
    public:
        
		//! = default
        OutMessage();
        OutMessage(std::set<SessionId> destinations, std::string content);
        
        //OutMessage(OutMessage&& other) = default; thanks VS

        //! default move constructor
        OutMessage(OutMessage&& other);
        
        
        
        //OutMessage& operator=(OutMessage&& other) = default;

        //! default move assignment
        OutMessage& operator=(OutMessage&& other);

        std::set<SessionId> const& destinations() const {
            return destionations_;
        }
        
        void removeDestination(SessionId sessionId);

        void keepDestinations(std::set<SessionId> const& keep);
        
        friend struct WebSocketQueue;
    };
    
    struct InMessage {
    private:
        SessionId source_;
        std::string content_;
        
    public:
        
        std::string const& content() const {
            return content_;
        }
        
        SessionId source() const {
            return source_;
        }
        
        InMessage();
        InMessage(SessionId source, char const* bytes, std::size_t len);
        
        friend struct WebSocketQueue;
    };

    //! So we don't have to include the libwebsockets header
    struct LibWebsocketsCallbackReasonBoxed;

    //! WebSocket server using the libwebsockets library
    struct WebSocketQueue {
    private:
        bool messageSent_;
        SessionId nextUniqueSessionId_;
        
        unsigned int maxSessionCount_;

        //! List of unique session ids, at the moment only one session at a time is possible
        std::set<SessionId> sessions_;

        libwebsocket_context *context_;

        mutable std::mutex mutex_;

        //Using list because resizing is costly

        //! Incoming messages, std::string has a nothrow move constructor, therefore
        //! resize should not be a problem
        std::deque<InMessage> inMessages_;

        //! Outgoing messages
        std::deque<OutMessage> outMessages_;
        
        std::deque<OutMessage>::iterator firstMessageWithDestination(SessionId sessionId);

    public:
        
        std::set<SessionId> sessions() const;
        
        //TODO: Make private somehow
        static int callback(libwebsocket_context *context, libwebsocket *wsi,
                            LibWebsocketsCallbackReasonBoxed const& reasonBoxed,
                            void *user, void *in, size_t len);
        
        //! send, empty, receive can be called from different threads use work only in the one thread
        //! Put message on queue to send
        void emit(OutMessage message);

        //! returns a list of new messages
        std::deque<InMessage> receive();

        //! call this to do the actual work: send and receiving messages handling network stuff ...
        void work();

        WebSocketQueue();
        ~WebSocketQueue();
    };

}

#endif
