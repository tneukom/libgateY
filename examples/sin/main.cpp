#include "../../gatey.hpp"
#include <thread>
#include <chrono>
#include <cmath>

/*
* Compile together with ../../gatey.cpp
* Windows need ws2_32.lib (Visual Studio will automatically add it because of #pragma comment(lib, "ws2_32.lib")
*/

int main() {
	std::chrono::milliseconds dura(20);
	gatey::global = std::make_shared<gatey::GateY>();
	
	gatey::WriteVariable<std::tuple<float, float>> gF("y");
	gatey::ReadVariable<float> gDt("dt", 0.01f);
	gatey::ReadVariable<float> gC("c", 1.0f);


	float time = 0.0f;
	while (true) {
		float y = gC.get() * std::sin(time);
		gF.set(std::make_pair(time, y));
		time += gDt.get();
		std::this_thread::sleep_for(dura);
	}

    return 0;
}

