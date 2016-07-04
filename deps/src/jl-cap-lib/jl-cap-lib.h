/*
 * =====================================================================================
 *
 *       Filename:  jl-cap-lib.h
 *
 *    Description:  includes for jl-cap-lib.c
 *
 *        Created:  06/26/2016 05:09:30 PM
 *       Compiler:  gcc
 *
 *         Author:  Brandon K. Miller (bkm), brandonkentmiller@gmail.com 
 *
 * =====================================================================================
 */

#ifndef _PCAP_H
#define _PCAP_H

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#define DEBUG 1

int _cap_open_live (const char *device, int snaplen, int promisc, int ms);
int _cap_set_filter (const char *filter);
void _cap_close (void);
int _cap_loop (int count);

#endif
