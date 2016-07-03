/*
 * =====================================================================================
 *
 *       Filename:  jl-cap-lib.c
 *
 *    Description:  wrappers for libpcap live _cap functionality
 *
 *        Created:  06/26/2016 05:06:29 PM
 *       Compiler:  gcc
 *
 *         Author:  Brandon K. Miller (bkm), brandonkentmiller@gmail.com 
 *
 * =====================================================================================
 */

#include "jl-cap-lib.h"

static pcap_t *_handle = NULL;
static char *_errbuf = NULL;
static struct bpf_program *_fp = NULL;
static bpf_u_int32 _mask;
static bpf_u_int32 _net;

static void cap_dispose(void)
{
    _net = 0;
    _mask = 0;
    free(_errbuf);
    _errbuf = NULL;
    pcap_freecode(_fp);
}

int _cap_open_live(const char *device, int snaplen, int promisc,
                      int ms)
{
    if (pcap_lookupnet(device, &_net, &_mask, _errbuf) == -1)
        return -1;

    if (_handle != NULL)
        return -1;

    _errbuf = (char *)malloc(PCAP_ERRBUF_SIZE);
    _handle = pcap_open_live(device, snaplen, promisc, ms, _errbuf);
    if (_handle == NULL)
        return -1;

    return (pcap_datalink(_handle));
}

int _cap_set_filter(const char *filter)
{
    _fp = (struct bpf_program *)malloc(sizeof(struct bpf_program));

    if (pcap_compile(_handle, _fp, filter, 0, _net) == -1)
        return -1;

    if (pcap_setfilter(_handle, _fp) == -1)
        return -1;
    
    return 0;
}

void _cap_close(void)
{
    if (_handle)
        pcap_close(_handle);
    cap_dispose();
}

void _cap_loop(void)
{
}
