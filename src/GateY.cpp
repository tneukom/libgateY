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
