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

#ifndef _H_FPGA_KMEANS_
#define _H_FPGA_KMEANS_
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans.h"

#define FLOAT_DT    0
#define INT_DT      1
#if USE_DATA_TYPE == INT_DT
    #define DATA_TYPE unsigned int 
    #define INT_DATA_TYPE int
#else
    #define DATA_TYPE float
    #define INT_DATA_TYPE int
#endif


void calculate_scale_factor(float* mem, int size);
DATA_TYPE* re_align_clusters(float** clusters, int n_clusters, int N_Features, int n_features);
DATA_TYPE* re_align_features(float** feature, int N_Features, int NPoints, int n_features, int n_points, int size);
float** fpga_kmeans_clustering(
                          float **feature,    /* in: [npoints][nfeatures] */
                          int     nfeatures,
                          int     npoints,
                          int     nclusters,
                          float   threshold,
                          int    *membership /* out: [npoints] */
        );

int fpga_kmeans_setup(int global_size = 1);
int fpga_kmeans_init();
int fpga_kmeans_shutdown();
int fpga_kmeans_allocate( int n_points, int n_features, int n_clusters, float **feature);
int fpga_kmeans_deallocateMemory();
int fpga_kmeans_print_report();
#endif // _H_FPGA_KMEANS_
