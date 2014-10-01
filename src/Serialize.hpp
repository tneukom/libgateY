/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_SERIALIZE_H
#define GATEY_SERIALIZE_H

#if defined(GATEY_USE_EXTERNAL_JSONCPP)
    #if defined(GATEY_EXTERNAL_JSONCPP_PATH)
        #include GATEY_EXTERNAL_JSONCPP_PATH
    #else
        #include <json/json.h>
    #endif
#else
    #if !defined(GATEY_IS_AMALGAMATION)
        #include "json.hpp"
    #endif
#endif

#include <functional>
#include <vector>
#include <array>
#include <map>
#include <memory>
#include <tuple>
#include <utility>

namespace gatey {
    
    namespace serialize {
        struct Info {
            Info() {
            }
        };
    }
    
    template<typename T>
    void read(Json::Value const& jValue, T& value) {
        serialize::Info info;
        read(jValue, value, info);
    }
    
    template<typename T>
    void write(T const& value, Json::Value& jValue) {
        serialize::Info info;
        write(value, jValue, info);
    }
    

    
    
    namespace serialize {


        
        //! serialize int
        void write(int value, Json::Value& jValue, Info const& info);
        
        //! deserialize int
        void read(Json::Value const& jValue, int& value, Info const& info);
        
        //! serialize float
        void write(float value, Json::Value& jValue, Info const& info);
        
        //! deserialize float
        void read(Json::Value const& jValue, float& value, Info const& info);
        
        //! serialize and deserialize double
        void write(double value, Json::Value& jValue, Info const& info);
        
        // read double from json
        void read(Json::Value const& jValue, double& value, Info const& info);
        
        //! serialize and deserialize char
        void write(char value, Json::Value& jValue, Info const& info);
        
        //! read char from json
        void read(Json::Value const& jValue, char& value, Info const& info);
        
        //! serialize and deserialize std::string
        void write(std::string const& value, Json::Value& jValue, Info const& info);
        
        //! read string from json
        void read(Json::Value const& jValue, std::string& value, Info const& info);
        
        //! serialize std::vector<T> of any type T that can be serialized
        template<typename T>
        void write(std::vector<T> const& items, Json::Value& jItems, Info const& info) {
            jItems = Json::Value(Json::arrayValue);
            for (T const& item : items) {
                write(item, jItems.append(Json::Value()), info);
            }
        }
        
        //! deserialize std::vector<T> of any type T that can be serialized
        template<typename T>
        void read(Json::Value const& jItems, std::vector<T>& items, Info const& info) {
            for(Json::Value const& jItem : jItems) {
                T item;
                read(jItem, item, info);
                items.push_back(item);
            }
        }
        
        //! serialize std::aray<T, SIZE> of any type T that can be serialized
        template<typename T, std::size_t SIZE>
        void write(std::array<T, SIZE> const& items, Json::Value& jItems, Info const& info) {
            jItems = Json::Value(Json::arrayValue);
            for (T const& item : items) {
                write(item, jItems.append(Json::Value()), info);
            }
        }
        
        //! deserialize std::aray<T, SIZE> of any type T that can be serialized
        template<typename T, std::size_t SIZE>
        void read(Json::Value const& jItems, std::array<T, SIZE>& items, Info const& info) {
            for (std::size_t i = 0; i < SIZE; ++i) {
                Json::Value const& jItem = jItems[(Json::Value::ArrayIndex)i];
                read(jItem, items[i], info);
            }
        }
        
        //! serialize std::map<std::string, T> of any type T that can be serialized
        template<typename T>
        void write(std::map<std::string, T> const& map, Json::Value& jMap, Info const& info) {
            jMap = Json::Value(Json::objectValue);
            for (auto const& pair : map) {
                std::string const& key = pair.first();
                T const& value = pair.second();
                write(value, jMap[key], info);
            }
        }
        
        //! deserialize std::map<std::string, T> of any type T that can be serialized
        template<typename T>
        void read(Json::Value const& jMap, std::map<std::string, T>& map, Info const& info) {
            for(auto iter = jMap.begin(); iter != jMap.end(); ++iter) {
                T value;
                read(*iter, value, info);
                map.emplace(iter.memberName(), value);
            }
        }
        
        //! serialize std::unique_ptr<T> of any type T that can be serialized
        template<typename T>
        void write(std::unique_ptr<T> const& ptr, Json::Value& jPtr, Info const& info) {
            write(*ptr, jPtr, info);
        }
        
        //! deserialize std::unique_ptr<T> of any type T that can be serialized
        template<typename T>
        void read(Json::Value const& jPtr, std::unique_ptr<T>& ptr, Info const& info) {
            //TODO: new?
            ptr.reset(new T);
            read(jPtr, *ptr, info);
        }
        
        //! serialize and deserialize std::shared_ptr<T> of any type T that can be serialized
        template<typename T>
        void write(std::shared_ptr<T> const& ptr, Json::Value& jPtr, Info const& info) {
            write(*ptr, jPtr, info);
        }
        
        template<typename T>
        void read(Json::Value const& jPtr, std::shared_ptr<T>& ptr, Info const& info) {
            ptr.reset(new T);
            read(jPtr, *ptr, info);
        }
        
        //std::tuple
        template<std::size_t I, std::size_t SIZE, typename TUPLE>
        struct SerializeTupleElements {
            static void writeTuple(TUPLE const& tuple, Json::Value& jTuple, Info const& info) {
                auto const& item = std::get<I>(tuple);
                write(item, jTuple.append(Json::Value()), info);
                SerializeTupleElements<I + 1, SIZE, TUPLE>::writeTuple(tuple, jTuple, info);
            }
            
            static void readTuple(Json::Value const& jTuple, TUPLE& tuple, Info const& info) {
                auto& item = std::get<I>(tuple);
                Json::Value const& jItem = jTuple[(Json::Value::ArrayIndex)I];
                read(jItem, item, info);
                SerializeTupleElements<I + 1, SIZE, TUPLE>::deserializeTuple(jTuple, tuple, info);
            }
        };
        
        template<std::size_t SIZE, typename TUPLE>
        struct SerializeTupleElements<SIZE, SIZE, TUPLE> {
            static void writeTuple(TUPLE const& tuple, Json::Value& jTuple, Info const& info) {
            }
            
            static void deserializeTuple(Json::Value const& jTuple, TUPLE& tuple, Info const& info) {
            }
        };

#if defined(_MSC_VER) && (_MSC_VER < 1800) //1800 is Visual Studio 2013

        template<typename ARG0, typename ARG1, typename ARG2, typename ARG3, typename ARG4, typename ARG5>
        void write(std::tuple<ARG0, ARG1, ARG2, ARG3, ARG4, ARG5> const& tuple, Json::Value& jTuple, Info const& info) {
            SerializeTupleElements<0, std::tuple_size<decltype(tuple)>::value, decltype(tuple)>::writeTuple(tuple, jTuple, info);
        }

        template<typename ARG0, typename ARG1, typename ARG2, typename ARG3, typename ARG4, typename ARG5>
        void read(Json::Value const& jTuple, std::tuple<ARG0, ARG1, ARG2, ARG3, ARG4, ARG5>& tuple, Info const& info) {
            SerializeTupleElements<0, std::tuple_size<decltype(tuple)>::value, decltype(tuple)>::readTuple(jTuple, tuple, info);
        }
        
#else
        
        template<typename... ARGS>
        void write(std::tuple<ARGS...> const& tuple, Json::Value& jTuple, Info const& info) {
            SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::writeTuple(tuple, jTuple, info);
        }
        
        template<typename... ARGS>
        void read(Json::Value const& jTuple, std::tuple<ARGS...>& tuple, Info const& info) {
            SerializeTupleElements<0, sizeof...(ARGS), std::tuple<ARGS...>>::readTuple(jTuple, tuple, info);
        }

#endif
        
        //void write(T const&, WriteArchive);
        //void read(ReadArchive, T&);
    }
    

    

}

#endif
