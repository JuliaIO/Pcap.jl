/*
 * =====================================================================================
 *
 *       Filename:  live_cap.c
 *
 *    Description:  wrappers for libpcap live capture functionality
 *
 *        Created:  06/26/2016 05:06:29 PM
 *       Compiler:  gcc
 *
 *         Author:  Brandon K. Miller (bkm), brandonkentmiller@gmail.com 
 *
 * =====================================================================================
 */

#include "live_cap.h"

int capture_open_live(const char *device, int snaplen, int promisc,
                      int to_ms)
{   
}

void capture_close(void)
{
}

void capture_loop(void)
{
}
