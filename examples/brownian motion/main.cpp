#include "../../gatey.hpp"
#include <thread>
#include <chrono>
#include <cmath>
#include <random>

/*
* Compile together with ../../gatey.cpp
* Windows need ws2_32.lib (Visual Studio will automatically add it because of #pragma comment(lib, "ws2_32.lib")
*/

int main() {
    gatey::global = std::make_shared<gatey::GateY>();

    std::tuple<float, float> position(300.0f, 300.0f);
    gatey::WriteVariable<std::tuple<float, float>> gPosition("position");
    gatey::ReadVariable<float> gDt("dt", 0.01f);

    std::mt19937 gen;
    std::normal_distribution<float> normal(0, 1);

    while (true) {
        std::get<0>(position) += gDt.get() * normal(gen);
        std::get<1>(position) += gDt.get() * normal(gen);
        gPosition.set(position);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return 0;
}

