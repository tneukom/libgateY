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
		JsonValue jMessage(Json::objectValue);
		jMessage["cmd"] = "state";

		JsonValue jReceiveGates(Json::objectValue);
		for (auto const& pair : receiveGates_) {
			jReceiveGates[pair.first] = JsonValue(Json::objectValue);
		}
		jMessage["receiveGates"] = jReceiveGates;

		JsonValue jSendGates(Json::objectValue);
		for (auto const& pair : sendGates_) {
			jSendGates[pair.first] = JsonValue(Json::objectValue);
		}
		jMessage["sendGates"] = jSendGates;

		sendUnsynced(jMessage);
	}

	void GateY::handleMessageUnsynced(std::string const& messageStr) {
		Json::Reader reader;
		JsonValue message;
		reader.parse(messageStr, message);

		std::string cmd = message["cmd"].asString();
		if (cmd == "state") {
			remoteReceiveGates_.clear();
			JsonValue const& jReceiveGates = message["receiveGates"];
			for (::Json::ValueConstIterator iter = jReceiveGates.begin(); iter != jReceiveGates.end(); ++iter) {
				RemoteReceiveGate remoteReceiveGate;
				std::string name = iter.memberName();
				remoteReceiveGates_.emplace(name, remoteReceiveGate);
			}

			remoteSendGates_.clear();
			JsonValue const& jSendGates = message["sendGates"];
			for (::Json::ValueConstIterator iter = jSendGates.begin(); iter != jSendGates.end(); ++iter) {
				RemoteSendGate remoteSendGate;
				std::string name = iter.memberName();
				remoteSendGates_.emplace(name, remoteSendGate);
			}
		}
		else if (cmd == "message") {
			std::string name = message["name"].asString();
			auto found = receiveGates_.find(name);
			if (found == receiveGates_.end()) {
				GATEY_LOG("received message without port");
				return;
			}

			ReceiveGate& gate = found->second;

			JsonValue const& content = message["content"];
			if (gate.receive_ != nullptr) {
				callbacks_.push_back(std::bind(gate.receive_, content));
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
            std::deque<std::string> messageStrs = webSocket_->receive();
			for (std::string const& messageStr : messageStrs) {
				handleMessageUnsynced(messageStr);
			}
		}

		//TODO: Check if syncing necessary
		webSocket_->work();

		processCallbacks();
	}


	void GateY::openReceiveGate(std::string const& name, std::function<void(JsonValue const& json)> receive) {
		std::lock_guard<std::mutex> guard(mutex_);

		auto found = receiveGates_.find(name);
		if (found != receiveGates_.end()) {
			//Gate with this name already exists just changing callback
			ReceiveGate& gate = found->second;
			gate.receive_ = receive;
			return;
		}

		ReceiveGate gate(receive);
		receiveGates_.emplace(name, gate);
		stateModified_ = true;
	}

	void GateY::openSendGate(std::string const& name) {
		std::lock_guard<std::mutex> guard(mutex_);

		auto found = sendGates_.find(name);
		if (found != sendGates_.end()) {
			//Gate with this name already exists just changing callback
			return;
		}

		SendGate gate;
		sendGates_.emplace(name, gate);
		stateModified_ = true;
	}

	void GateY::sendUnsynced(JsonValue const& json) {
		Json::FastWriter jsonWriter;
		std::string messageStr = jsonWriter.write(json);
		webSocket_->send(messageStr);
	}

	void GateY::send(std::string const& name, JsonValue const& content) {
		auto foundLocalGate = sendGates_.find(name);
		if (foundLocalGate == sendGates_.end()) {
			GATEY_LOG("can't send message, no local send gate open with name: " + name);
			return;
		}

		auto foundRemoteGate = remoteReceiveGates_.find(name);
		if (foundRemoteGate == remoteReceiveGates_.end()) {
			GATEY_LOG("can't send message, no remote receive gate open with name: " + name);
			return;
		}

		JsonValue message;
		message["cmd"] = "message";
		message["name"] = name;
		message["content"] = content;
		sendUnsynced(message);
	}

	void GateY::closeReceiveGateUnsynced(std::string const& name) {
		auto found = receiveGates_.find(name);
		if (found == receiveGates_.end()) {
			GATEY_LOG("no gate to delete with name: " + name);
			return;
		}

		receiveGates_.erase(found);
		stateModified_ = true;
	}

	void GateY::closeSendGateUnsynced(std::string const& name) {
		auto found = sendGates_.find(name);
		if (found == sendGates_.end()) {
			GATEY_LOG("no gate to close with name: " + name);
			return;
		}

		sendGates_.erase(found);
		stateModified_ = true;
	}

	void GateY::closeReceiveGate(std::string const& name) {
		std::lock_guard<std::mutex> guard(mutex_);
		closeReceiveGateUnsynced(name);
	}

	void GateY::closeSendGate(std::string const& name) {
		std::lock_guard<std::mutex> guard(mutex_);
		closeSendGateUnsynced(name);
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

}
