#ifndef INSIDER_H
#define INSIDER_H

#define _GNU_SOURCE //因为使用了readline和getpagesize函数，所以要加这个宏，gnu里面有这两个函数，标准c库没有
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

//#define DEBUG_MODE

#define PAGEMAP_ENTRY 8   // pagemap文件中，一个entry占64bit，即8bytes
#define GET_BIT(X,Y) (X & ((uint64_t)1<<Y)) >> Y
#define GET_PFN(X) X & 0x7FFFFFFFFFFFFF  //

// translate the virtual address to the physical address
// return -1 when the address is illegal
int read_pagemap(int pid, unsigned long virt_addr, uint64_t* phy_addr, uint64_t* page_frame_num);

#endif