CXX = g++ -O2

all: double_pendulum lorenz_attractor


double_pendulum: double_pendulum.cpp
	$(CXX) double_pendulum.cpp -lm -o double_pendulum

lorenz_attractor: lorenz_attractor.cpp
	$(CXX) lorenz_attractor.cpp -lm -o lorenz_attractor


clean:
	rm -f double_pendulum lorenz_attractor



