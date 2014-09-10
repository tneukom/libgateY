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
    
    namespace serialize {
        
        //int
        void write(int value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, int& value, Info const& info) {
            value = jValue.asInt();
        }
        
        
        //float
        void write(float value, Json::Value& jValue, Info const& info) {
            if (!std::isfinite(value)) {
                jValue = Json::Value(0.0f);
                std::cerr << "encountered nan or inf" << std::endl;
            }
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, float& value, Info const& info) {
            value = jValue.asFloat();
        }
        
        //double
        void write(double value, Json::Value& jValue, Info const& info) {
            if (!std::isfinite(value)) {
                jValue = Json::Value(0.0f);
                std::cerr << "encountered nan or inf" << std::endl;
            }
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, double& value, Info const& info) {
            value = jValue.asDouble();
        }
        
        //char
        void write(char value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(std::string(value, 1));
        }
        
        void read(Json::Value const& jValue, char& value, Info const& info) {
            //TODO: Check if single char
            value = jValue.asCString()[0];
        }
        
        //std::string
        void write(std::string const& value, Json::Value& jValue, Info const& info) {
            jValue = Json::Value(value);
        }
        
        void read(Json::Value const& jValue, std::string& value, Info const& info) {
            value = jValue.asString();
        }

    } // namespace serialize




} // namespace gatey
