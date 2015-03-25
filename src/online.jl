export pcap_lookupdev, pcap_findalldevs

type SockAddr
    sa_family::Cushort
    sa_data1::Cuchar
    sa_data2::Cuchar
    sa_data3::Cuchar
    sa_data4::Cuchar
    sa_data5::Cuchar
    sa_data6::Cuchar
    sa_data7::Cuchar
    sa_data8::Cuchar
    sa_data9::Cuchar
    sa_data10::Cuchar
    sa_data11::Cuchar
    sa_data12::Cuchar
    sa_data13::Cuchar
    sa_data14::Cuchar

    function SockAddr()
        new(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    end # constructor
end # type SockAddr

type PcapAddr
    next::Ptr{Void}
    addr::Ptr{Void}
    netmask::Ptr{Void}
    broadaddr::Ptr{Void}
    dstaddr::Ptr{Void}

    function PcapAddr()
        next      = C_NULL
        addr      = C_NULL
        netmask   = C_NULL
        broadaddr = C_NULL
        dstaddr   = C_NULL
        new(next, addr, netmask,
            broadaddr, dstaddr)
    end # constructor
end # type PcapAddr

type PcapIf
    next::Ptr{Void} # PcapIf
    name::Ptr{Uint8}
    description::Ptr{Uint8}
    addresses::Ptr{Void} # PcapAddr
    flags::Cint

    function PcapIf()
        next        = C_NULL
        name        = C_NULL
        description = C_NULL
        addresses   = C_NULL
        flags       = 0

        new(next, name, description,
            addresses, flags)
    end # constructor
end # type PcapIf

# ----------
# lookup all devices
# ----------
function pcap_findalldevs()
    # TODO: somethings not right
    alldevs = PcapIf()
    errbuff::Ptr{Uint8} = C_NULL
    status = ccall((:pcap_findalldevs, "libpcap"), Cint, (Ptr{PcapIf}, Ptr{UInt8}), &alldevs, errbuff)
    alldevs
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
