/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_LOG_HPP
#define GATEY_LOG_HPP

//#define GATEY_LOG_ENABLED

#ifdef GATEY_LOG_ENABLED

#include <string>

namespace gatey {
	void log(const char* str);
	void log(std::string const& str);
}

#define GATEY_LOG(str) gatey::log(str)

#else //GATEY_LOG_ENABLED
#define GATEY_LOG (void)
#endif //GATEY_LOG_ENABLED


#endif //GATEY_LOG_HPP