/*
 * Copyright(C) 2014 Tobias Neukom <tneukom@gmail.com>
 * Distributed under MIT license
 */

#ifndef GATEY_IS_AMALGAMATION
#include "Log.hpp"
#endif

#include <string>
#include <iostream>

namespace gatey {
	void log(const char* str) {
		std::cout << str << std::endl;
	}

	void log(std::string const& str) {
		std::cout << str << std::endl;
	}
}

