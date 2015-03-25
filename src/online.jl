export pcap_lookupdev, pcap_findalldevs

immutable SockAddr
    sa_family::Uint16
    sa_data1::Uint8
    sa_data2::Uint8
    sa_data3::Uint8
    sa_data4::Uint8
    sa_data5::Uint8
    sa_data6::Uint8
    sa_data7::Uint8
    sa_data8::Uint8
    sa_data9::Uint8
    sa_data10::Uint8
    sa_data11::Uint8
    sa_data12::Uint8
    sa_data13::Uint8
    sa_data14::Uint8
end # immutable SockAddr

immutable PcapAddr
    next::Ptr{PcapAddr}
    addr::Ptr{SockAddr}
    netmask::Ptr{SockAddr}
    broadaddr::Ptr{SockAddr}
    dstaddr::Ptr{SockAddr}

    function PcapAddr()
        next      = C_NULL
        addr      = C_NULL
        netmask   = C_NULL
        broadaddr = C_NULL
        dstaddr   = C_NULL
        new(next, addr, netmask,
            broadaddr, dstaddr)
    end # constructor
end # immutable PcapAddr

immutable PcapIf
    next::Ptr{PcapIf}
    name::Ptr{Uint8}
    description::Ptr{Uint8}
    addresses::Ptr{PcapAddr}
    flags::Int32

    function PcapIf()
        next        = C_NULL
        name        = C_NULL
        description = C_NULL
        addresses   = C_NULL
        flags       = 0

        new(next, name, description,
            addresses, flags)
    end # constructor
end # immutable PcapIf

#int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
#void pcap_freealldevs(pcap_if_t *alldevs);

function pcap_findalldevs()
    alldevsp = PcapIf()
    errbuff  = Ptr{Uint8}
    status = ccall((:pcap_findalldevs, "libpcap"), Int32, (Ptr{Ptr{PcapIf}}, Ptr{UInt8}), &alldevsp, errbuff)
end # function pcap_findalldevs

# ----------
# lookup default device
# ----------
function pcap_lookupdev()
    dev = ccall((:pcap_lookupdev, "libpcap"), Ptr{UInt8}, ())
    if dev == C_NULL
        return Union()
    end
    bytestring(dev)
end # function pcap_lookupdev
