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
