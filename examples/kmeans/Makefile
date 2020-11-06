CC := g
CXX := $(CXX)
CPPFLAGS := $(CPPFLAGS) -I.. 
CFLAGS := $(CFLAGS) -I..
CXXFLAGS := $(CXXFLAGS) -I.. -std=c++0x
LDFLAGS := $(LDFLAGS) -L.. -lz
VACCELRT_KMEANS_DT := INT
ifeq ($(VACCELRT_KMEANS_DT), INT)
	DATATYPE_ID = 1
else
	DATATYPE_ID = 0
endif

.PHONY: all clean xilinx_libs

all: test_km

xilinx_libs: ../xilinx_libs/logger/logger.o ../xilinx_libs/cmdparser/cmdlineparser.o

CXXFLAGS := $(CXXFLAGS) -D USE_DATA_TYPE=$(DATATYPE_ID)
%.o: %.cpp
	$(CXX) -c $^ -o $@ $(CXXFLAGS)

%.o: %.c
	$(CXX) -c $^ -o $@ $(CFLAGS)

CXXFLAGS += -I../xilinx_libs/logger -I../xilinx_libs/cmdparser
../xilinx_libs/%/%.o: ../xilinx_libs/%/%.cpp
	$(CXX) -c $^ -o $@ $(CXXFLAGS)

DEPENDS = test_km.o cluster.o rmse.o fpga_kmeans.o kmeans_clustering_cmodel.o
DEPENDS += ../xilinx_libs/logger/logger.o ../xilinx_libs/cmdparser/cmdlineparser.o
LDFLAGS := $(LDFLAGS) -lpthread -lrt
test_km: $(DEPENDS)
	$(CXX) $^ -o $@ $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(DEPENDS) speed_km
