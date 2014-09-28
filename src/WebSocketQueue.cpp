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
