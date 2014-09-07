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
#include <map>
#include <mutex>
#include <string>
#include <memory>
#include <thread>

namespace gatey {

    struct WebSocketQueue;
    
    enum class Location {
        Local,
        Remote
    };
    
    enum class Direction {
        Send,
        Receive
    };
    
    struct Gate {
        std::string name;
        Location location; //local for this
        Direction direction;
        SessionId sessionId; //undefined for location == Local
        std::function<void()> callback; //undefiend for location == remote
    };
    
//    Gate {
//        name = "position",
//        location = Local,
//        direction = Receive,
//        callback = ?
//    }
    
    
//    Gate {
//        name = "position",
//        localtion = Local,
//        direction = Send,
//    }
    
    
    
    // Should it be possible to subscribe to a local channel?
    // subscribeLocal(string name);

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
        
        std::vector<Gate> gates_;

        //! List of callback that have to be called, callbacks aren't called while
        //! mutex_ is locked because the callback should be able to call GateY functions
        //! They are collected and called at a later time
		std::vector<std::function<void()>> callbacks_;

        //! Send a json package to remote
		void sendUnsynced(JsonConstRef json);

        //! Send a list of open send and receive gates to remote
		void sendStateUnsynced();

        //! Handle a message receive from remote, messages include:
        //! - state change
        //! - content
        //! - init
		void handleMessageUnsynced(std::string const& messageStr);


        //! Calls all the callbacks_ and clears it
		void processCallbacks();

        //! Handles new messages from webSocket_
		void work();

        //! Close the receive gate with the given name and sends a state update
		void closeReceiveGateUnsynced(std::string const& name);

        //! Close the send gate with the given name
		void closeSendGateUnsynced(std::string const& name);

        //! Start the server
        void start();

	public:
        //! Starts the server
		GateY();

        //! Stops the server
		~GateY();

        //! subscribe to the channel with the given name
        //! The callback can call functions from GateY
		void subscribe(std::string const& name, std::function<void(JsonConstRef json)> receive);
        
        //! Stop receiving messages from name
		void unsubscribe(std::string const& name);
        
        
        void openReceiveGate(std::string name)
        
        //! Announce a station
        void openSendGate(std::string name);
        
        //! Close a station
        void closeSendGate();

        //! Send a message to all remote clients that subscribed to name
		void publish(std::string const& name, JsonConstRef json);
	};

    //! global GateY, Variables use this global gateY to open gates
	extern std::shared_ptr<GateY> global;

}


#endif //GATEY_GATEY_H

