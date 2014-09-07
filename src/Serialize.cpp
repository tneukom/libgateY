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
    JsonConstRef::JsonConstRef(Json::Value const& json) : json_(json) {
        
    }

    JsonConstRef JsonConstRef::at(std::size_t i) const {
        return json_[(Json::Value::ArrayIndex)i];
    }
    
    JsonConstRef JsonConstRef::at(std::string const& key) const {
        return json_[key];
    }
    
    
    
    //! applies f to each element in the json list
    void JsonConstRef::forEach(std::function<void(JsonConstRef)> f) {
        for (Json::Value const& item : json_) {
            f(item);
        }
    }
    
    //! applies f to each key and value in the json object
    void JsonConstRef::forEach(std::function<void(std::string const&, JsonConstRef)> f) {
        for (auto iter = json_.begin(); iter != json_.end(); ++iter) {
            f(iter.memberName(), *iter);
        }
    }
    

    JsonRef::JsonRef(Json::Value& json) : json_(json) {
    }

    void JsonRef::list() {
        json_ = Json::Value(Json::arrayValue);
    }
    
    void JsonRef::object() {
        json_ = Json::Value(Json::objectValue);
    }
    
    JsonRef JsonRef::append() {
        return json_.append(Json::Value(Json::nullValue));
    }
    
    JsonRef JsonRef::key(std::string const& key) {
        return json_[key];
    }
    
    JsonHolder::JsonHolder() : holder_(new Json::Value(Json::nullValue)) {
    }
    
    JsonHolder::~JsonHolder() {
    }
    

    JsonRef JsonHolder::operator*() {
        return *holder_;
    }

	void serialize(int value, JsonRef json) {
        json.json_ = Json::Value(value);
    }
    
	void deserialize(JsonConstRef json, int& value) {
        value = json.json_.asInt();
    }
    
    
    
	//double
	void serialize(double value, JsonRef json) {
		if (!std::isfinite(value)) {
			json.json_ = Json::Value(0.0f);
			std::cerr << "encountered nan or inf" << std::endl;
		}
		json.json_ = Json::Value(value);
	}
    
	void deserialize(JsonConstRef json, double& value) {
		value = json.json_.asFloat();
	}
    
    //float
	//TODO: How to handle nan and +-inf in json?
    void serialize(float value, JsonRef json) {
        if (!std::isfinite(value)) {
			json.json_ = Json::Value(0.0f);
			std::cerr << "encountered nan or inf" << std::endl;
		}
		json.json_ = Json::Value(value);
    }
    
	void deserialize(JsonConstRef json, float& value) {
        value = json.json_.asFloat();
    }
    
    //char
	void serialize(char value, JsonRef json) {
        json.json_ = Json::Value(std::string(value, 1));
    }
    
	void deserialize(JsonConstRef json, char& value) {
        //TODO: Check if single char
        value = json.json_.asCString()[0];
    }
    
    //std::string
	void serialize(std::string const& str, JsonRef json) {
        json.json_ = Json::Value(str);
    }
    
	void deserialize(JsonConstRef json, std::string& value) {
        value = json.json_.asString();
    }

}
