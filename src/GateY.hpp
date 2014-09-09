/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_GATEY_H
#define GATEY_GATEY_H

#ifndef GATEY_IS_AMALGAMATION
#include "Serialize.hpp"
#include "WebSocketQueue.hpp"
#endif

#include <vector>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <memory>
#include <thread>

namespace gatey {

    struct WebSocketQueue;

    //! internal
	struct Emitter {
        std::string name_;
        
        Emitter() = default;
        
        Emitter(std::string name) :
            name_(std::move(name))
        {
        }
	};

    //! internal
	struct Subscription {
        std::string name_;
        // std::string identifier_; maybe in the future
		std::function<void(JsonConstRef json)> receive_;
        
        Subscription() = default;
        
        Subscription(std::string name, std::function<void(JsonConstRef json)> receive) :
            name_(std::move(name)),
            receive_(std::move(receive))
        {
        }
	};
    
    //! internal
	struct RemoteEmitter {
        std::string name_;
        SessionId sessionId_;
        
        RemoteEmitter() = default;
        
        RemoteEmitter(std::string name, SessionId sessionId) :
            name_(std::move(name)),
            sessionId_(sessionId)
        {
        }
	};

    //! internal
	struct RemoteSubscription {
        std::string name_;
        SessionId sessionId_;
        
        RemoteSubscription() = default;
        
        RemoteSubscription(std::string name, SessionId sessionId) :
            name_(std::move(name)),
            sessionId_(sessionId)
        {
        }
	};



    //! open and close gates, which come in two forms: receive gates and send gates
    //! messages can be sent over send gates and a receive gate on the remote side will
    //! process them.
    //! If a message is sent over a send gate and the remote side doesn't have a corresponding
    //! receive gate, the message is discarded
    //! If gates are opened or closes the remote side will be notified automatically
    //! Functions with the Unsynced postfix don't lock on mutex_ all other functions lock mutex_
	struct GateY {
	private:
        //! true if any gates were opened or closed
		bool stateModified_;

		//! is true while thread_ is running
		bool running_;

        //! WebSocket server which does the actual network stuff
		std::unique_ptr<WebSocketQueue> webSocket_;

        //! Runs the network and dispatching work
		std::thread thread_;
		std::mutex mutex_;

#if defined(_MSC_VER)
		//! msvc deadlocks if thread::join is called after main exits, see ~GateY for more details
		std::mutex mutexThreadRunning_;
#endif

		std::vector<Subscription> subscriptions_;
		std::vector<RemoteSubscription> remoteSubscriptions_;
		std::vector<Emitter> emitters_;
		std::vector<RemoteEmitter> remoteEmitters_;

        //! List of callback that have to be called, callbacks aren't called while
        //! mutex_ is locked because the callback should be able to call GateY functions
        //! They are collected and called at a later time
		std::vector<std::function<void()>> callbacks_;

        //! Send a json package to remote
		void sendUnsynced(std::set<SessionId> sessions, JsonConstRef json);
        
        //! Send a json package to all remotes
        void broadcastUnsynced(JsonConstRef json);

        //! Send a list of open send and receive gates to remote
		void sendStateUnsynced();

        //! Handle a message receive from remote, messages include:
        //! - state change
        //! - content
        //! - init
		void handleMessageUnsynced(InMessage const& message);


        //! Calls all the callbacks_ and clears it
		void processCallbacks();

        //! Handles new messages from webSocket_
		void work();

        //! Close the receive gate with the given name and sends a state update
		void unsubscribeUnsynced(std::string const& name);

        //! Close the send gate with the given name
		void closeEmitterUnsynced(std::string const& name);

        //! Start the server
        void start();
        
        std::vector<Subscription>::iterator findSubscriptionUnsynced(std::string const& name);
        
        std::vector<Emitter>::iterator findEmitterUnsynced(std::string const& name);
        
        std::vector<RemoteEmitter>::iterator findRemoteEmitterUnsynced(std::string const& name);
        
        std::vector<RemoteSubscription>::iterator findRemoteSubscriptionUnsynced(std::string const& name);
        
        std::set<SessionId> collectRemoteSubscriptions(std::string const& name);

	public:
        
        //! Starts the server
		GateY();

        //! Stops the server
		~GateY();
        
        // Subscribe to receive all messages with the given name
        void subscribe(std::string const& name, std::function<void(JsonConstRef json)> receive);
        
        // Unsubscribe from receiving messages with the given name
        void unsubscribe(std::string const& name);
        
        // Send a message with the given name
        void emit(std::string const& name, JsonConstRef json);
        
        // Announce the sending of message with the given name
        void openEmitter(std::string const& name);
        
        // Unannounce the sending of messages with the given name
        void closeEmitter(std::string const& name);
        
	};

    //! global GateY, Variables use this global gateY to open gates
	extern std::shared_ptr<GateY> global;

}


#endif //GATEY_GATEY_H

