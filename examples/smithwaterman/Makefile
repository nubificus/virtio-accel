CC := gcc
CXX := g++
CPPFLAGS := $(CPPFLAGS) -I.. 
CFLAGS := $(CFLAGS) -I..
CXXFLAGS := $(CXXFLAGS) -I.. -std=c++0x
LDFLAGS := $(LDFLAGS) -L.. -lz
LIBS := -fopenmp

.PHONY: all clean xilinx_libs

all: test_sw

xilinx_libs: logger.o cmdlineparser.o

%.o: %.cpp
	$(CXX) -c $^ -o $@ $(CXXFLAGS)

intel/%.o: intel/%.c
	$(CXX) -c $^ -o $@ $(CFLAGS)

CXXFLAGS += -I../xilinx_libs/logger -I../xilinx_libs/cmdparser
../xilinx_libs/%/%.o: ../xilinx_libs/%/%.cpp
	$(CXX) -c $^ -o $@ $(CXXFLAGS)

DEPENDS = test_sw.o matcharray.o genseq.o smithwaterman.o
DEPENDS += intel/sc_demo.o intel/ssw.o
DEPENDS += ../xilinx_libs/logger/logger.o ../xilinx_libs/cmdparser/cmdlineparser.o
test_sw: $(DEPENDS)
	$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(DEPENDS) test_sw
