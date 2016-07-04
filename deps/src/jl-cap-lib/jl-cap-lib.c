/*
 * =====================================================================================
 *
 *       Filename:  jl-cap-lib.c
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

#include "jl-cap-lib.h"

struct self
{
    pcap_t *handle;
    char *errbuf;
    struct bpf_program *fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
};

static struct self _self;

static void cap_dispose(void)
{
    _self.net = 0;
    _self.mask = 0;
    free(_self.errbuf);
    _self.errbuf = NULL;
    if (_self.fp)
    {
        pcap_freecode(_self.fp);
        _self.fp = NULL;
    }
}

static void process_record(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
#ifdef DEBUG
    printf("+ received a packet\n");
#endif
}

int _cap_open_live(const char *device, int snaplen, int promisc,
                      int ms)
{
    if (pcap_lookupnet(device, &_self.net, &_self.mask, _self.errbuf) == -1)
        return -1;

    if (_self.handle != NULL)
        return -1;

    _self.errbuf = (char *)malloc(PCAP_ERRBUF_SIZE);
    _self.handle = pcap_open_live(device, snaplen, promisc, ms, _self.errbuf);
    if (_self.handle == NULL)
        return -1;

    return (pcap_datalink(_self.handle));
}

int _cap_set_filter(const char *filter)
{
    _self.fp = (struct bpf_program *)malloc(sizeof(struct bpf_program));

    if (pcap_compile(_self.handle, _self.fp, filter, 0, _self.net) == -1)
        return -1;

    if (pcap_setfilter(_self.handle, _self.fp) == -1)
        return -1;
    
    return 0;
}

void _cap_close(void)
{
    if (_self.handle)
        pcap_close(_self.handle);
    cap_dispose();
}

int _cap_loop(int count)
{
    return (pcap_loop(_self.handle, count, process_record, NULL));
}
