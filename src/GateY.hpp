/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_GATEY_H
#define GATEY_GATEY_H

#ifndef GATEY_IS_AMALGAMATION
#include "Serialize.hpp"
#endif

#include <vector>
#include <map>
#include <mutex>
#include <string>
#include <memory>
#include <thread>

namespace gatey {

    struct WebSocketQueue;

    //! internal
	struct SendGate {
	};

    //! internal
	struct ReceiveGate {
		std::function<void(JsonValue const& json)> receive_;

		ReceiveGate(std::function<void(JsonValue const& json)> receive) :
			receive_(receive)
		{
		}
	};

    //! internal
	struct RemoteSendGate {
	};

    //! internal
	struct RemoteReceiveGate {
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

		std::map<std::string, ReceiveGate> receiveGates_;
		std::map<std::string, RemoteReceiveGate> remoteReceiveGates_;
		std::map<std::string, SendGate> sendGates_;
		std::map<std::string, RemoteSendGate> remoteSendGates_;

        //! List of callback that have to be called, callbacks aren't called while
        //! mutex_ is locked because the callback should be able to call GateY functions
        //! They are collected and called at a later time
		std::vector<std::function<void()>> callbacks_;

        //! Send a json package to remote
		void sendUnsynced(JsonValue const& json);

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

		//! Open receive gate, messages get forwarded to receive function
        //! The callback can call functions from GateY
		void openReceiveGate(std::string const& name, std::function<void(JsonValue const& json)> receive);

        //! Open a send gate
		void openSendGate(std::string const& name);

        //! Send a message over the send gate with the given name, the message is only sent if: there is an open
        //! send the with the given name and there is an open remote receive gate with the given name.
		void send(std::string const& name, JsonValue const& json);

		//! Closes a recieve gate
		void closeReceiveGate(std::string const& name);

		//! Close a send gate
		void closeSendGate(std::string const& name);
	};

    //! global GateY, Variables use this global gateY to open gates
	extern std::shared_ptr<GateY> global;

}


#endif //GATEY_GATEY_H

