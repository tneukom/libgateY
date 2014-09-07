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
    
    struct JsonHolder;
    struct JsonConstRef;
    struct GateY;
    
    struct JsonRef {
    private:
        Json::Value& json_;
        
        JsonRef(Json::Value& json);
        
    public:
        
        //! turns the json value into a json list
		void list();
        
        //! turns the json value into a json object
		void object();
        
        //! appends a new json value to jsonList and returns a reference to it
		JsonRef append();
        
        //! return a reference to the json value with the given key in jsonObject, if
        //! the key doesn't exist it is created
		JsonRef key(std::string const& key);
        
        friend struct JsonHolder;
        friend struct JsonConstRef;
        friend struct GateY;
        
        friend void serialize(int value, JsonRef json);
        friend void serialize(float value, JsonRef json);
        friend void serialize(double value, JsonRef json);
        friend void serialize(char value, JsonRef json);
        friend void serialize(std::string const& str, JsonRef json);
    };

    
    struct JsonConstRef {
    private:
        Json::Value const& json_;
        
        JsonConstRef(Json::Value const& json);
        
    public:
        
        JsonConstRef(JsonRef other) : json_(other.json_) {
        }
        
        //! returns the json value at index i
		JsonConstRef at(std::size_t i) const;
        
        //! returns the json value with the given key
        //! TODO: Make sure key is not created
		JsonConstRef at(std::string const& key) const;
        
        //! applies f to each element in the json list
        void forEach(std::function<void(JsonConstRef)> f);
        
        //! applies f to each key and value in the json object
        void forEach(std::function<void(std::string const&, JsonConstRef)> f);
        
        friend struct GateY;
        
        friend void deserialize(JsonConstRef json, int& value);
        friend void deserialize(JsonConstRef json, float& value);
        friend void deserialize(JsonConstRef json, double& value);
        friend void deserialize(JsonConstRef json, char& value);
        friend void deserialize(JsonConstRef json, std::string& value);
    };
    

    
    struct JsonHolder {
    private:
        std::unique_ptr<Json::Value> holder_;
        
    public:
        JsonHolder();
        ~JsonHolder();
        
        JsonRef operator*();
    };

    //! serialize int
	void serialize(int value, JsonRef json);

    //! deserialize int
	void deserialize(JsonConstRef json, int& value);

    //! serialize float
    void serialize(float value, JsonRef json);

    //! deserialize float
	void deserialize(JsonConstRef json, float& value);

    //! serialize and deserialize double
	void serialize(double value, JsonRef json);
	void deserialize(JsonConstRef json, double& value);

    //! serialize and deserialize char
	void serialize(char value, JsonRef json);
	void deserialize(JsonConstRef json, char& value);

    //! serialize and deserialize std::string
	void serialize(std::string const& str, JsonRef json);
	void deserialize(JsonConstRef json, std::string& value);

    //! serialize std::vector<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::vector<T> const& items, JsonRef json) {
		json.list();
		for (T const& item : items) {
			serialize(item, json.append());
		}
	}

    //! deserialize std::vector<T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonConstRef json, std::vector<T>& items) {
        json.forEach([&items](JsonConstRef jsonItem) {
			T item;
			deserialize(jsonItem, item);
			items.push_back(item);
		});
	}

    //! serialize std::aray<T, SIZE> of any type T that can be serialized
	template<typename T, std::size_t SIZE>
	void serialize(std::array<T, SIZE> const& items, JsonRef json) {
        json.list();
		for (T const& item : items) {
			serialize(item, json.append());
		}
	}

    //! deserialize std::aray<T, SIZE> of any type T that can be serialized
	template<typename T, std::size_t SIZE>
	void deserialize(JsonConstRef json, std::array<T, SIZE>& items) {
		for (std::size_t i = 0; i < SIZE; ++i) {
            JsonConstRef jsonItem = json.at(i);
			deserialize(jsonItem, items[i]);
		}
	}

    //! serialize std::map<std::string, T> of any type T that can be serialized
	template<typename T>
	void serialize(std::map<std::string, T> const& map, JsonRef json) {
		json.object();
		for (auto const& pair : map) {
            std::string const& key = pair.first();
            T const& value = pair.second();
			serialize(value, json.key(key));
		}
	}

    //! deserialize std::map<std::string, T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonConstRef json, std::map<std::string, T>& map) {
        json.forEach([&map](std::string const& key, JsonConstRef jsonValue) {
			T value;
            deserialize(jsonValue, value);
			map.emplace(key, value);
		});
	}

    //! serialize std::unique_ptr<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::unique_ptr<T> const& ptr, JsonRef json) {
		serialize(*ptr, json);
	}

    //! deserialize std::unique_ptr<T> of any type T that can be serialized
	template<typename T>
	void deserialize(JsonConstRef json, std::unique_ptr<T>& ptr) {
		*ptr = T();
		deserialize(json, *ptr);
	}

    //! serialize and deserialize std::shared_ptr<T> of any type T that can be serialized
	template<typename T>
	void serialize(std::shared_ptr<T> const& ptr, JsonRef json) {
		serialize(*ptr, json);
	}

	template<typename T>
	void deserialize(JsonConstRef json, std::shared_ptr<T>& ptr) {
		*ptr = T();
		deserialize(json, *ptr);
	}

	//std::tuple
	template<std::size_t I, std::size_t SIZE, typename TUPLE>
	struct SerializeTupleElements {
		static void serializeTuple(TUPLE const& tuple, JsonRef jTuple) {
			auto const& item = std::get<I>(tuple);
			JsonRef jItem = jTuple.append();
			serialize(item, jItem);
			SerializeTupleElements<I + 1, SIZE, TUPLE>::serializeTuple(tuple, jTuple);
		}

		static void deserializeTuple(JsonConstRef jTuple, TUPLE& tuple) {
			auto& item = std::get<I>(tuple);
			JsonConstRef jItem = jTuple.at(I);
            deserialize(jItem, item);
			SerializeTupleElements<I + 1, SIZE, TUPLE>::deserializeTuple(jTuple, tuple);
		}
	};

	template<std::size_t SIZE, typename TUPLE>
    struct SerializeTupleElements<SIZE, SIZE, TUPLE> {
		static void serializeTuple(TUPLE const& tuple, JsonRef jTuple) {
		}

		static void deserializeTuple(JsonConstRef jTuple, TUPLE& tuple) {
		}
	};

    template<typename... ARGS>
	void serialize(std::tuple<ARGS...> const& tuple, JsonRef json) {
		SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::serializeTuple(tuple, json);
	}

	template<typename... ARGS>
	void deserialize(JsonConstRef json, std::tuple<ARGS...>& tuple) {
		SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::deserializeTuple(json, tuple);
	}
}

#endif
