/*
 * =====================================================================================
 *
 *       Filename:  pcap-lib.h
 *
 *    Description:  includes for pcap-lib.c
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
#include <pcap/pcap.h>

int capture_open_live (const char *device, int snaplen, int promisc, int ms);
int capture_set_filter (const char *filter);
void capture_close (void);
void capture_loop (void);

#endif
