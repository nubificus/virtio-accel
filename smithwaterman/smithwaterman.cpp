/**********
Copyright (c) 2017, Xilinx, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********/
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "smithwaterman.h"
#include "xilinx_libs/logger/logger.h"
#include "sw.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include "../accel.h"
#include <vaccel_runtime.h>
#include <arpa/inet.h>

#if defined(__linux__) || defined(linux)
	#include "sys/time.h"
#elif defined(WIN32)
	#include "windows.h"
#endif

//ROUNDS <= 10 valid
typedef struct _eventLog {
    double totalWrite;
    double totalRead;
    double totalExecute;
} eventLog;

using namespace sda;
using namespace sda::cl;

unsigned int* generatePackedNReadRefPair(int N, int readSize, int refSize, unsigned int** maxVal, size_t *bufSize, int computeOutput = 1);

/////////////////////////////////////////////////////////////////////////////////
static double timestamp() {
	double ms = 0.0;
	#if  defined(__linux__) || defined(linux)
		timeval time;
		gettimeofday(&time, NULL);
		ms = (time.tv_sec * 1000.0) + (time.tv_usec / 1000.0);
	#elif defined(WIN32)
		SYSTEMTIME time;
		GetSystemTime(&time);
		ms = (time.wSeconds * 1000) + time.wMilliseconds;
	#endif
	return ms;
}

#if 0
static double computeEventDurationInMS(const cl_event& event) {
	cl_ulong ts_start = 0, ts_end = 0;
	double duration = 0;
	clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &ts_start, NULL);
	clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &ts_end, NULL);
	duration += (cl_double)(ts_end-ts_start)*(cl_double)(1e-06);

	return duration;
}
#endif

static int getToken(FILE* fp, char* tok)
{
    int pos = 0;
    char ch;
    while ((ch = (char)(fgetc(fp)))) {
        if (ch == EOF) {
            return 0;
        }
        if (ch == ' ') {
            continue;
        }
        if (ch == ',' || ch == '\n') {
            tok[pos] = '\0';
            return 1;
        }
        tok[pos++] = ch;
    }
    return -1;
}

static int readReadRefFile(char* fname, unsigned int** pairs, unsigned int** maxv, int N, size_t *bufSize)
{
    FILE* fp = fopen(fname, "r");
    char* string = new char[1024];
    int rdSz = 0;
    int refSz = 0;
    int sampleNum = 0;
    int numInt = 0;
    int numSamples;
    while ((sampleNum < N) && getToken(fp, string)) {
        if (!strcmp(string, "rdsz")) {
            getToken(fp, string);
            rdSz = atoi(string);
        }
        if (!strcmp(string, "refsz")) {
            getToken(fp, string);
            refSz = atoi(string);
        }
        if (!strcmp(string, "samples")) {
            getToken(fp, string);
            numSamples = atoi(string);
            assert(N <= numSamples);
            printf("Reading %d samples out of %d in the file\n", N, numSamples);
            numInt = READREFUINTSZ(rdSz, refSz);
            *pairs = new unsigned int[N * numInt];
			*bufSize = sizeof(unsigned int) * N * numInt;
            *maxv = new unsigned int[3 * N];
        }
        if (string[0] == 'S') {
            for (int p = 0; p < numInt; ++p) {
                getToken(fp, string);
                unsigned int val = (unsigned int)atoll(string);
                (*pairs)[sampleNum * numInt + p] = val;
            }
            for (int p = 0; p < 3; ++p) {
                getToken(fp, string);
                unsigned int val = (unsigned int)atoll(string);
                (*maxv)[sampleNum * 3 + p] = val;
            }
            sampleNum++;
        }
    }
    delete[] string;
    fclose(fp);
    return sampleNum;
}

static int verify(int numSample, unsigned int* outputGolden, unsigned int* output)
{
    int fail = 0;
    printf("Verifying computed MAXSORE returned to HOST\n");
    for (int i = 0; i < numSample; ++i) {
        int localFail = 0;
        if (outputGolden[3 * i + 2] != output[3 * i + 2]) {
            fail = 1;
            localFail = i + 1;
        }
        if (localFail) {
            printf("Fail %d:", localFail - 1);
            for (int j = 0; j < 3; ++j) {
                printf("g=%u, m=%u, ", outputGolden[3 * i + j], output[3 * i + j]);
            }
        }
    }
    if (fail) {
        printf("Fail\n");
    }
    else {
        printf("Pass\n");
    }
    return fail;
}

/////////////////////////////////////////////////////////////////////////////////
SmithWatermanApp::SmithWatermanApp(const string& vendor_name,
    const string& device_name,
    int selected_device,
    const string& strKernelFP,
    const string& strSampleFP,
    const int numBlocks,
    const int blkSz,
    const bool doubleBuffered,
    const bool verifyMode,
    const bool writeMatchArray,
    MatchArray* pm)
    
{
	struct vaccelrt_hdr sess_hdr;
	struct accel_gen_op_arg sess_outargs;
	int ret;

    //store path to input bitmap
    m_strSampleFP = strSampleFP;
    m_numSamples = numBlocks * blkSz * NUMPACKED;
    m_useDoubleBuffered = doubleBuffered;
    m_numBlocks = numBlocks;
    m_blockSz = blkSz;
    m_verifyMode = verifyMode;
    m_pMatchInfo = pm;
    m_writeMatchArray = writeMatchArray;
#if 0
    m_world = xcl_world_single();

    m_program = xcl_import_binary(m_world, "krnl_smithwaterman");
   //kernels
    m_clKernelSmithWaterman = xcl_get_kernel(m_program, "opencl_sw_maxscore");
#endif

	if ((m_fd = open("/dev/accel", O_RDWR, 0)) < 0) {
		perror("open()");
	}

	sess_hdr.type = VACCELRT_SESS_SW;
	sess_outargs.buf = (__u8 *)&sess_hdr;
	sess_outargs.len = sizeof(struct vaccelrt_hdr);

	memset(&m_sess, 0, sizeof(m_sess));
	m_sess.u.gen.in_nr = 0;
	m_sess.u.gen.out_nr = 1;
	m_sess.u.gen.out = &sess_outargs;
	m_sess.u.gen.in = NULL;

	if (ioctl(m_fd, ACCIOC_GEN_SESS_CREATE, &m_sess)) {
		perror("ioctl(ACCIOC_GEN_SESS_CREATE)");
	}
}

SmithWatermanApp::~SmithWatermanApp()
{
#if 0
    clReleaseKernel(m_clKernelSmithWaterman);
    clReleaseProgram(m_program);
    xcl_release_world(m_world);
#endif
	if (ioctl(m_fd, ACCIOC_GEN_SESS_DESTROY, &m_sess)) {
		perror("ioctl(ACCIOC_GEN_SESS_DESTROY)");
	}
}

bool SmithWatermanApp::unit_test_kernel_cpu()
{

    LogInfo("Start unit tests for kernels on the CPU");

    LogInfo("End unit tests for kernels on the CPU");

    return true;
}

/*!
 * Unit test for the huffman cpu version
 */
bool SmithWatermanApp::unit_test_naive()
{
    return true;
}

bool SmithWatermanApp::invoke_kernel(
    unsigned int* input,
    unsigned int* output,
    int* iterNum,
    int sz_input,
    int sz_output,
    int sz_sz,
	size_t sz_b_input,
	size_t sz_b_output,
    double eTotal[evtCount])
{
#if 0
	if (m_useDoubleBuffered) {
        bool res = invoke_kernel_doublebuffered(input, output, iterNum, sz_input, sz_output, sz_sz, &events[0], eTotal);
        if (!res) {
            LogError("Failed Double Buffered SW. Test Failed");
            return false;
        }
    }
    else {
#endif
        bool res = invoke_kernel_blocking(input, output, iterNum, sz_input, sz_output, sz_sz, sz_b_input, sz_b_output, eTotal);
        if (!res) {
            LogError("Failed Blocked SW. Test Failed");
            return false;
        }
#if 0
    }
#endif

    return true;
}

bool SmithWatermanApp::invoke_kernel_blocking(
    unsigned int* input,
    unsigned int* output,
    int* iterNum,
    int sz_input,
    int sz_output,
    int sz_sz,
	size_t sz_b_input,
	size_t sz_b_output,
    double eTotal[evtCount])
{
	struct accel_op op;
	struct vaccelrt_hdr sess_hdr;
	struct accel_gen_op_arg op_args[3];
	int ret;

	memset(&sess_hdr, 0, sizeof(sess_hdr));
	sess_hdr.u.sw.blk_size = htonl(*iterNum);
	sess_hdr.u.sw.nblocks = htonl(m_numBlocks);
	sess_hdr.u.sw.sz_input = htonl(sz_input);
	sess_hdr.u.sw.sz_output = htonl(sz_output);
	memset(&op, 0, sizeof(op));
	op.session_id = m_sess.id;
	op_args[0].len = sizeof(sess_hdr);
	op_args[0].buf = (__u8 *)&sess_hdr;
	op_args[1].len = sz_b_input;
	op_args[1].buf = (__u8 *)input;
	op_args[2].len = sz_b_output;
	op_args[2].buf = (__u8 *)output;
	op.u.gen.in_nr = 1;
	op.u.gen.out_nr = 2;
	op.u.gen.out = &op_args[0];
	op.u.gen.in = &op_args[2];

	if (ret = ioctl(m_fd, ACCIOC_GEN_DO_OP, &op)) {
		perror("ioctl(ACCIOC_GEN_DO_OP)");
		return false;
	}

    return true;
}

#if 0
bool SmithWatermanApp::invoke_kernel_doublebuffered(
    unsigned int* input,
    unsigned int* output,
    int* iterNum,
    int sz_input,
    int sz_output,
    int sz_sz,
    cl_event events[evtCount],
    double eTotal[evtCount])
{

    cl_kernel kernel = m_clKernelSmithWaterman;

    cl_int err;
    cl_mem mem_input_ping;
    mem_input_ping = clCreateBuffer(m_world.context, CL_MEM_READ_WRITE, sz_input, NULL, &err);
    if (err != CL_SUCCESS) {
        LogError("Error: Failed to allocate OpenCL source buffer of size %lu", sz_input);
        return false;
    }

    cl_mem mem_input_pong;
    mem_input_pong = clCreateBuffer(m_world.context, CL_MEM_READ_WRITE, sz_input, NULL, &err);
    if (err != CL_SUCCESS) {
        LogError("Error: Failed to allocate OpenCL source buffer of size %lu", sz_input);
        return false;
    }

    cl_mem mem_output_ping;
    mem_output_ping = clCreateBuffer(m_world.context, CL_MEM_READ_WRITE, sz_output, NULL, &err);
    if (err != CL_SUCCESS) {
        LogError("Failed to allocate worst case OpenCL output buffer of size %lu",
            sz_input);
        return false;
    }

    cl_mem mem_output_pong;
    mem_output_pong = clCreateBuffer(m_world.context, CL_MEM_READ_WRITE, sz_output, NULL, &err);
    if (err != CL_SUCCESS) {
        LogError("Failed to allocate worst case OpenCL output buffer of size %lu",
            sz_input);
        return false;
    }

    cl_mem mem_sz_sz;
    mem_sz_sz = clCreateBuffer(m_world.context, CL_MEM_READ_WRITE, sz_sz, NULL, &err);
    if (err != CL_SUCCESS) {
        LogError("Failed to allocate worst case OpenCL output buffer of size %lu",
            sizeof(u32));
        return false;
    }

    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &mem_sz_sz);
    if (err != CL_SUCCESS) {
        LogError("Failed to set kernel argument [2] sz_output! %d", err);
        LogError("Test failed");
        return false;
    }

    cl_event ping[3];
    cl_event pong[3];

    int numIter = m_numBlocks;
    cout << "Processing " << m_numSamples << " Samples \n";
    if (numIter >= 1) {
        err = clEnqueueWriteBuffer(m_world.command_queue, mem_input_ping, CL_FALSE, 0,
            sz_input, input, 0, NULL, &ping[evtHostWrite]);
        assert(err == CL_SUCCESS);
        err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mem_input_ping);
        assert(err == CL_SUCCESS);
        err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mem_output_ping);
        assert(err == CL_SUCCESS);

        if (numIter > 1) {
            err = clEnqueueWriteBuffer(m_world.command_queue, mem_input_pong, CL_FALSE, 0,
                sz_input, (input + (sz_input / sizeof(unsigned int))), 0, NULL, &pong[evtHostWrite]);
        }
        assert(err == CL_SUCCESS);
        err = clEnqueueTask(m_world.command_queue, kernel, 0, NULL, &ping[evtKernelExec]);
        assert(err == CL_SUCCESS);
        err = clEnqueueReadBuffer(m_world.command_queue, mem_output_ping, CL_FALSE, 0,
            sz_output, output, 1, &ping[evtKernelExec], &ping[evtHostRead]);
        assert(err == CL_SUCCESS);
    }

    if (numIter >= 2) {
        err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mem_input_pong);
        assert(err == CL_SUCCESS);

        err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mem_output_pong);
        assert(err == CL_SUCCESS);
        if (numIter > 2) {
            err = clWaitForEvents(1, &ping[evtHostWrite]);
            assert(err == CL_SUCCESS);
            err = clEnqueueWriteBuffer(m_world.command_queue, mem_input_ping, CL_FALSE, 0,
                sz_input, (input + (sz_input / sizeof(unsigned int))), 0, NULL, &ping[evtHostWrite]);
            assert(err == CL_SUCCESS);
        }

        //call once to guarentee that all buffers are migrated to device memory
        err = clEnqueueTask(m_world.command_queue, kernel, 0, NULL, &pong[evtKernelExec]);
        assert(err == CL_SUCCESS);

        //read output size
        err = clEnqueueReadBuffer(m_world.command_queue, mem_output_pong, CL_FALSE, 0,
            sz_output, (output + (sz_output / sizeof(unsigned int))), 1, &pong[evtKernelExec], &pong[evtHostRead]);
        assert(err == CL_SUCCESS);
    }

    for (int iter = 2; iter < numIter; ++iter) {
        //copy input dataset to OpenCL buffer
        //cout << "In iteration" << iter << "\n";
        if (iter & 1) { //pong
            err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mem_input_pong);
            assert(err == CL_SUCCESS);

            err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mem_output_pong);
            assert(err == CL_SUCCESS);
            if (iter < numIter - 1) {
                err = clWaitForEvents(1, &ping[evtHostWrite]);
                assert(err == CL_SUCCESS);
                err = clEnqueueWriteBuffer(m_world.command_queue, mem_input_ping, CL_FALSE, 0,
                    sz_input, (input + (iter + 1) * (sz_input / sizeof(unsigned int))), 0, NULL, &ping[evtHostWrite]);
                assert(err == CL_SUCCESS);
            }

            //finish all memory writes

            //call once to guarentee that all buffers are migrated to device memory
            err = clWaitForEvents(2, pong);
            assert(err == CL_SUCCESS);
            err = clEnqueueTask(m_world.command_queue, kernel, 0, NULL, &pong[evtKernelExec]);
            assert(err == CL_SUCCESS);

            //read output size
            err = clWaitForEvents(2, pong + 1);
            assert(err == CL_SUCCESS);
            err = clEnqueueReadBuffer(m_world.command_queue, mem_output_pong, CL_FALSE, 0,
                sz_output, (output + iter * (sz_output / sizeof(unsigned int))), 0, NULL, &pong[evtHostRead]);
            assert(err == CL_SUCCESS);
        }
        else { //ping
            err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mem_input_ping);
            assert(err == CL_SUCCESS);
            err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &mem_output_ping);
            assert(err == CL_SUCCESS);
            if (iter < numIter - 1) {
                err = clWaitForEvents(1, &pong[evtHostWrite]);
                assert(err == CL_SUCCESS);
                err = clEnqueueWriteBuffer(m_world.command_queue, mem_input_pong, CL_FALSE, 0,
                    sz_input, (input + (iter + 1) * (sz_input / sizeof(unsigned int))), 0, NULL, &pong[evtHostWrite]);
                assert(err == CL_SUCCESS);
            }

            //call once to guarentee that all buffers are migrated to device memory
            err = clWaitForEvents(2, ping);
            assert(err == CL_SUCCESS);
            err = clEnqueueTask(m_world.command_queue, kernel, 0, NULL, &ping[evtKernelExec]);
            assert(err == CL_SUCCESS);

            //read output size
            err = clWaitForEvents(2, ping + 1);
            assert(err == CL_SUCCESS);
            err = clEnqueueReadBuffer(m_world.command_queue, mem_output_ping, CL_FALSE, 0,
                sz_output, (output + iter * (sz_output / sizeof(unsigned int))), 0, NULL, &ping[evtHostRead]);
            assert(err == CL_SUCCESS);
        }
        eTotal[evtHostWrite] += computeEventDurationInMS(events[evtHostWrite]);
        eTotal[evtKernelExec] += computeEventDurationInMS(events[evtKernelExec]);
        eTotal[evtHostRead] += computeEventDurationInMS(events[evtHostRead]);
    }
    clFinish(m_world.command_queue);

    //cleanup
    releaseMemObject(mem_input_ping);
    releaseMemObject(mem_output_ping);
    releaseMemObject(mem_input_pong);
    releaseMemObject(mem_output_pong);
    releaseMemObject(mem_sz_sz);

    return true;
}
#endif

bool SmithWatermanApp::run(int idevice, int nruns)
{
    if (nruns <= 0)
        return false;

    assert(unit_test_kernel_cpu());

    int err;
    unsigned int* output;
    unsigned int* outputGolden;
    unsigned int* input;
	size_t inBufSz, outBufSz;
    int* iterNum;
    int hwBlockSize = NUMPACKED * m_blockSz;
    int totalSamples = m_numSamples;
    cout << "------FPGA Accelerator Summary --------\n";
    cout << "Number of SmithWaterman instances on FPGA:" << NUMPACKED << "\n";
    cout << "Total processing elements:" << MAXPE * NUMPACKED << "\n";
    cout << "Length of reference string:" << MAXCOL << "\n";
    cout << "Length of read(query) string:" << MAXROW << "\n";
    cout << "Read-Ref pair block size(HOST to FPGA):" << m_blockSz << "\n";
    cout << "Verify Mode is:" << m_verifyMode << "\n";
    cout << "---------------------------------------\n";

    //seed random
    srand(time(NULL));

    if (m_verifyMode) {
        cout << "Reading read-ref samples\n";
        err = readReadRefFile((char*)m_strSampleFP.c_str(), &input, &outputGolden, totalSamples, &inBufSz);
        if (err != totalSamples) {
            LogError("Unable to read sample file: [%s]", m_strSampleFP.c_str());
            return false;
        }
    }
    else {
        cout << "Generating read-ref samples\n";
        input = generatePackedNReadRefPair(totalSamples, MAXROW, MAXCOL, &outputGolden, &inBufSz, 0); //do not generate compute output
    }

    //input buffer size
    int inSz = sizeof(unsigned int) * (hwBlockSize * PACKEDSZ);
    int outSz = sizeof(unsigned int) * (hwBlockSize * 3);
    int szSz = sizeof(unsigned int);

    output = new unsigned int[totalSamples * 3];
	outBufSz = sizeof(unsigned int) * totalSamples * 3;
    iterNum = new int;
    *iterNum = m_blockSz;

    //timings
    double eTotal[evtCount];
    double durations[evtCount];
    for (int i = 0; i < evtCount; i++) {
        durations[i] = 0.0;
        eTotal[i] = 0.0;
    }

    //start time stamps
    double startMS = timestamp();

    //execute
    for (int i = 0; i < nruns; i++) {
        bool res = invoke_kernel(input, output, iterNum, inSz, outSz, szSz,
						inBufSz, outBufSz, eTotal);
        if (!res) {
            LogError("Failed to encode the input. Test Failed");
            return false;
        }

        if (m_writeMatchArray) {
            m_pMatchInfo->populateArray(input, output);
            m_pMatchInfo->dumpArray();
        }

        //usleep(100);
    }

#if 0
    //collect times
    for (int i = 0; i < evtCount; i++) {
        durations[i] += computeEventDurationInMS(events[i]);
    }
#endif

	double totaltime = timestamp() - startMS;
    //set stats to valid data
	LogInfo("nruns = %u", nruns);
	LogInfo("total [ms] = %.3f", totaltime);
#if 0
	LogInfo("Host write [ms] = %.3f", eTotal[evtHostWrite]);
	LogInfo("Krnl exec [ms] = %.3f", eTotal[evtKernelExec]);
	LogInfo("Host read [ms] = %.3f", eTotal[evtHostRead]);

   
    float gcups = (float)(totalSamples / (eTotal[evtKernelExec]));
    gcups = gcups / (1024 * 1024 * 1.024);
    gcups = gcups * MAXROW * MAXCOL;
	cout << "GCups(based on kernel execution time):" << gcups << "\n";
#endif
    float gcups = (float)(totalSamples / (totaltime));
    gcups = gcups / (1024 * 1024 * 1.024);
    gcups = gcups * MAXROW * MAXCOL;
    cout << "GCups(based on total execution time):" << gcups << "\n";

#if 0
    //compute transfer rate for host write
    if (eTotal[evtHostWrite] > 0) {
        u32 sz_bytes = inSz * m_numBlocks;

        //bits per second
        double tmp = (sz_bytes * 8.0) / (eTotal[evtHostWrite] / 1000.0);

        //mega-bits per second
        tmp = tmp / (1024.0 * 1024.0);
		LogInfo("Host2Device rate [mbps] = %.3f", tmp);
    }

    //compute transfer rate for host read
    if (eTotal[evtHostRead] > 0) {
        u32 sz_bytes = outSz * m_numBlocks;

        //bits per second
        double tmp = (sz_bytes * 8.0) / (eTotal[evtHostRead] / 1000.0);

        //mega-bits per second
        tmp = tmp / (1024.0 * 1024.0);
		LogInfo("Device2Host rate [mbps] = %.3f", tmp);
    }
#endif

    if (m_verifyMode) {
        verify(totalSamples, outputGolden, output);
    }

    delete[] input;
    delete[] output;
    delete iterNum;
    return true;
}

