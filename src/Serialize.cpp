/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "Serialize.hpp"
#include "json.hpp"
#endif

#include <cmath>
#include <cassert>
#include <iostream>

namespace gatey {
	namespace json {
		Holder::Holder() : json_(new JsonValue(::Json::nullValue)) {

		}

		Holder::~Holder() {

		}

		JsonValue& Holder::operator*() {
			return *json_;
		}

		void list(JsonValue& json) {
			json = JsonValue(Json::arrayValue);
		}

		void object(JsonValue& json) {
			json = JsonValue(Json::objectValue);
		}

		JsonValue& append(JsonValue& jsonList) {
			return jsonList.append(JsonValue(Json::nullValue));
		}

		JsonValue& at(JsonValue& jsonObject, std::string const& key) {
			return jsonObject[key];
		}

		JsonValue const& at(JsonValue const& jsonList, std::size_t i) {
			return jsonList[(JsonValue::ArrayIndex)i];
		}

		JsonValue const& at(JsonValue const& jsonObject, std::string const& key) {
			return jsonObject[key];
		}

        void forEach(JsonValue const& jsonList, std::function<void(JsonValue const&)> f) {
			for (JsonValue const& item : jsonList) {
				f(item);
			}
		}

        void forEach(JsonValue const& jsonObject, std::function<void(std::string const&, JsonValue const&)> f) {
			for (auto iter = jsonObject.begin(); iter != jsonObject.end(); ++iter) {
				f(iter.memberName(), *iter);
			}
		}
	}

	//char
	void serialize(char value, JsonValue& json) {
		json = JsonValue(std::string(value, 1));
	}

	void deserialize(JsonValue const& json, char& value) {
		value = json.asCString()[0];
	}

	//int
	void serialize(int value, JsonValue& json) {
		json = JsonValue(value);
	}

	void deserialize(JsonValue const& json, int& value) {
		value = json.asInt();
	}

	//float
	//TODO: How to handle nan and +-inf in json?
	void serialize(float value, JsonValue& json) {
		if (!std::isfinite(value)) {
			json = JsonValue(0.0f);
			std::cerr << "encountered nan or inf" << std::endl;
		}
		json = JsonValue(value);
	}

	void deserialize(JsonValue const& json, float& value) {
		value = json.asFloat();
	}

	//double
	void serialize(double value, JsonValue& json) {
		if (!std::isfinite(value)) {
			json = JsonValue(0.0f);
			std::cerr << "encountered nan or inf" << std::endl;
		}
		json = JsonValue(value);
	}

	void deserialize(JsonValue const& json, double& value) {
		value = json.asFloat();
	}

	//std::string
	void serialize(std::string const& str, JsonValue& json) {
		json = JsonValue(str);
	}

	void deserialize(JsonValue const& json, std::string& value) {
		value = json.asString();
	}

}
