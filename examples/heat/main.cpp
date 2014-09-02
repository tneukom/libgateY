#include "../../gatey.hpp"
#include <thread>
#include <chrono>
#include <cmath>
#include <iostream>

/*
 * Compile together with ../../gatey.cpp
 * Windows need ws2_32.lib (Visual Studio will automatically add it because of #pragma comment(lib, "ws2_32.lib")
 */

int main() {
	std::chrono::milliseconds dura(20);
	gatey::global = std::make_shared<gatey::GateY>();

	const std::size_t SIZE = 32;
	std::array<std::array<double, SIZE>, SIZE> field = { { 0.0 } };
	std::tuple<int, std::string> tuple;
	gatey::WriteVariable<decltype(field)> gField("field");
	gatey::WriteVariable<decltype(tuple)> gTuple("tuple");

	field[SIZE / 2][SIZE / 2] = 100000.0;
	double alpha = 1.0;
	double dt = 1.0 / 30;
	while (true) {
		std::cout << "Enter key to start heat equation" << std::endl;
		char c;
		std::cin >> c;

		tuple = std::make_tuple(1, std::string("Hello World"));
		gTuple.set(tuple);

		for (unsigned int step = 0; step < 100; ++step) {
			std::this_thread::sleep_for(dura);

			decltype(field) copy = { { 0.0 } };
			for (std::size_t x = 1; x < SIZE - 1; ++x) {
				for (std::size_t y = 1; y < SIZE - 1; ++y) {
					//du/dt = alpha laplace u
					//du = dt * alpha laplace u
					//u' = u + dt * alpha laplace u
					double laplace = field[x - 1][y] + field[x + 1][y] + field[x][y - 1] + field[x][y + 1] - 4 * field[x][y];
					copy[x][y] = field[x][y] + alpha * dt * laplace;
				}
			}
			field = copy;
			gField.set(field);
		}
	}





 

    return 0;


}

