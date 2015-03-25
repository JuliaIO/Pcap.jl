export pcap_lookupdev, pcap_findalldevs

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
