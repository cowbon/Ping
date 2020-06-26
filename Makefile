all: ping

ping:
	$(CXX) main.cpp -o ping

.PHONY: all clean
clean:
	rm ping
