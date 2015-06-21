export pcap_lookupdev

#----------
# lookup default device
#----------
function pcap_lookupdev()
    dev = ccall((:pcap_lookupdev, "libpcap"), Ptr{UInt8}, ())
    if dev == C_NULL
        return Union()
    end
    bytestring(dev)
end # function pcap_lookupdev
