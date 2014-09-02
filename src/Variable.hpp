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
