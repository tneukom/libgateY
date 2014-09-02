// gatey amalgated header (http://jsoncpp.sourceforge.net/).
#ifndef GATEY_AMALGATED_H_INCLUDED
#define GATEY_AMALGATED_H_INCLUDED
#define GATEY_IS_AMALGAMATION

/* gateY code
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

/***************************************************
 * src/Serialize.hpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_SERIALIZE_H
#define GATEY_SERIALIZE_H

#include <functional>
#include <vector>
#include <array>
#include <map>
#include <memory>
#include <tuple>
#include <utility> 

namespace Json {
	class Value;
}

namespace gatey {

	typedef ::Json::Value JsonValue;

    //! hiding the json implementation, currently JsonCpp
	namespace json {
        //! Pimpl basically, so the header doesn't have to include the jsoncpp header
		struct Holder {
		private:
			std::unique_ptr<JsonValue> json_;

		public:
			Holder();
			~Holder();

			JsonValue& operator*();
		};

        //! turns the json value into a json list
		void list(JsonValue& json);

        //! turns the json value into a json object
		void object(JsonValue& json);

        //! appends a new json value to jsonList and returns a reference to it
		JsonValue& append(JsonValue& jsonList);

        //! return a reference to the json value with the given key in jsonObject, if
        //! the key doesn't exist it is created
		JsonValue& at(JsonValue& jsonObject, std::string const& key);

        //! returns the json value at index i
		JsonValue const& at(JsonValue const& jsonList, std::size_t i);

        //! returns the json value with the given key
        //! TODO: Make sure key is not created
		JsonValue const& at(JsonValue const& jsonObject, std::string const& key);

        //! applies f to each element in the json list
        void forEach(JsonValue const& jsonList, std::function<void(JsonValue const&)> f);

        //! applies f to each key and value in the json object
        void forEach(JsonValue const& jsonObject, std::function<void(std::string const&, JsonValue const&)> f);
	}

    //! serialize int
	void serialize(int value, JsonValue& json);

    //! deserialize int
	void deserialize(JsonValue const& json, int& value);

    //! serialize float
    void serialize(float value, JsonValue& json);

    //! deserialize float
	void deserialize(JsonValue const& json, float& value);

    //! serialize and deserialize double
	void serialize(double value, JsonValue& json);
	void deserialize(JsonValue const& json, double& value);

    //! serialize and deserialize char
	void serialize(char value, JsonValue& json);
	void deserialize(JsonValue const& json, char& value);

    //! serialize and deserialize std::string
	void serialize(std::string const& str, JsonValue& json);
	void deserialize(JsonValue const& json, std::string& value);

    //! serialize std::vector<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::vector<T> const& items, JsonValue& json) {
		json::list(json);
		for (T const& item : items) {
			serialize(item, json::append(json));
		}
	}

    //! deserialize std::vector<T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonValue const& json, std::vector<T>& items) {
        json::forEach(json, [&items](JsonValue const& jsonItem) {
			T item;
			deserialize(jsonItem, item);
			items.push_back(item);
		});
	}

    //! serialize std::aray<T, SIZE> of any type T that can be serialized
	template<typename T, std::size_t SIZE>
	void serialize(std::array<T, SIZE> const& items, JsonValue& json) {
		json::list(json);
		for (T const& item : items) {
			serialize(item, json::append(json));
		}
	}

    //! deserialize std::aray<T, SIZE> of any type T that can be serialized
	template<typename T, std::size_t SIZE>
	void deserialize(JsonValue const& json, std::array<T, SIZE>& items) {
		for (std::size_t i = 0; i < SIZE; ++i) {
			JsonValue const& jsonItem = json::at(json, i);
			deserialize(jsonItem, items[i]);
		}
	}

    //! serialize std::map<std::string, T> of any type T that can be serialized
	template<typename T>
	void serialize(std::map<std::string, T> const& map, JsonValue& json) {
		json::object(json);
		for (auto const& pair : map) {
			JsonValue& jsonValue = json::at(json, pair.first());
			serialize(pair.second(), jsonValue);
		}
	}

    //! deserialize std::map<std::string, T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonValue const& json, std::map<std::string, T>& map) {
        json::forEach(json, [&map](std::string const& key, JsonValue const& jsonValue) {
			T value;
            deserialize(jsonValue, value);
			map.emplace(key, value);
		});
	}

    //! serialize std::unique_ptr<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::unique_ptr<T> const& ptr, JsonValue& json) {
		serialize(*ptr, json);
	}

    //! deserialize std::unique_ptr<T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonValue const& json, std::unique_ptr<T>& ptr) {
		*ptr = T();
		deserialize(json, *ptr);
	}

    //! serialize and deserialize std::shared_ptr<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::shared_ptr<T> const& ptr, JsonValue& json) {
		serialize(*ptr, json);
	}

	template<typename T>
	void deserialize(JsonValue const& json, std::shared_ptr<T>& ptr) {
		*ptr = T();
		deserialize(json, *ptr);
	}

	//std::tuple
	template<std::size_t I, std::size_t SIZE, typename TUPLE>
	struct SerializeTupleElements {
		static void serializeTuple(TUPLE const& tuple, JsonValue& jTuple) {
			auto const& item = std::get<I>(tuple);
			JsonValue& jItem = json::append(jTuple);
			serialize(item, jItem);
			SerializeTupleElements<I + 1, SIZE, TUPLE>::serializeTuple(tuple, jTuple);
		}

		static void deserializeTuple(JsonValue const& jTuple, TUPLE& tuple) {
			auto& item = std::get<I>(tuple);
			JsonValue const& jItem = json::at(jTuple, I);
            deserialize(jItem, item);
			SerializeTupleElements<I + 1, SIZE, TUPLE>::deserializeTuple(jTuple, tuple);
		}
	};

	template<std::size_t SIZE, typename TUPLE>
    struct SerializeTupleElements<SIZE, SIZE, TUPLE> {
		static void serializeTuple(TUPLE const& tuple, JsonValue& jTuple) {
		}

		static void deserializeTuple(JsonValue const& jTuple, TUPLE& tuple) {
		}
	};

    template<typename... ARGS>
	void serialize(std::tuple<ARGS...> const& tuple, JsonValue& json) {
		SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::serializeTuple(tuple, json);
	}

	template<typename... ARGS>
	void deserialize(JsonValue const& json, std::tuple<ARGS...>& tuple) {
		SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::deserializeTuple(json, tuple);
	}
}

#endif

/***************************************************
 * src/GateY.hpp
 ***************************************************/

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


/***************************************************
 * src/Variable.hpp
 ***************************************************/

/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_VARIABLE_HPP
#define GATEY_VARIABLE_HPP

#ifndef GATEY_IS_AMALGAMATION
#include "GateY.hpp"
#endif

#include <string>
#include <thread>

namespace gatey {

	//! WriteVariable of type T that is connected to a remote ReadVariable, if it is set the remote ReadVariable
	//! will reflect the change
	//TODO: add emplace, for example for tuple: emplace(x, y) instead of set(std::make_tuple(x, y))
	template<typename T>
	struct WriteVariable {
	private:
		std::string name_;

		//! GateY used to send changes
		std::shared_ptr<GateY> gateY_;

	public:

		//! Using the given gatey or gatey::global as default, opens a send gate with the given name
		WriteVariable(std::string name, std::shared_ptr<GateY> gateY = gatey::global) :
            name_(std::move(name)),
			gateY_(gateY)
		{
			gateY_->openSendGate(name_);
		}

		//! Closes the send gate with the given name
		~WriteVariable() {
			gateY_->closeSendGate(name_);		
		}

		//! Set the value of this variable, the value is serialized to json using the gatey::serialize function
		//! and then sent to remote if it has a corresponding ReadVariable
		//TODO: Only serialize if 
		void set(T const& value) {
			json::Holder json;
			serialize(value, *json);
			gateY_->send(name_, *json);
		}
	};

	//! ReadVariable of type T that is connected to a remote WriteVariable, if the remote WriteVariable is
	//! changed, the change is reflected in the ReadVariable
    template<typename T>
	struct ReadVariable {
	private:
		std::string name_;

		//! current value
		T content_;

		//! to make sure the variable doesn't change while being read
		std::recursive_mutex mutex_;

		//! GateY used to receive changes
		std::shared_ptr<GateY> gateY_;

	public:
		std::function<void(T const& content)> onChange;

		//! Using the given gatey or gatey::global as default, opens a read gate with the given name,
		//! get will return content if the remote WriteVariable was never set.
		ReadVariable(std::string name, T content, std::shared_ptr<GateY> gateY = gatey::global) :
			name_(std::move(name)),
			content_(std::move(content)),
			gateY_(gateY)
		{
			gateY_->openReceiveGate(name_, [this](JsonValue const& jMessage) {
				std::lock_guard<std::recursive_mutex> guard(mutex_);
				deserialize(jMessage, content_);
				if (onChange != nullptr)
					onChange(content_);
			});
		}

		//! Closes the receive gate with the given name
		~ReadVariable() {
			gateY_->closeReceiveGate(name_);
		}

		//! Returns the current value, locks while the variable is being updated
		T get() {
			std::lock_guard<std::recursive_mutex> guard(mutex_);
			return content_;
		}
	};
}

#endif // GATEY_VARIABLE_HPP

#endif //ifndef GATEY_AMALGATED_H_INCLUDED