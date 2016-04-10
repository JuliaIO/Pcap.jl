##Pcap [![Build Status](https://travis-ci.org/brandonkmiller/Pcap.jl.svg?branch=master)](https://travis-ci.org/brandonkmiller/Pcap.jl)

Pcap contains libpcap bindings for Julia as well as logic to parse and extract useful data from packet captures

###Example
```julia
function display_eth_hdr(ethhdr::EthHdr)
    println("Ethernet Header")
    println("  |- Src Mac  : $(ethhdr.src_mac)")
    println("  |- Dest Mac : $(ethhdr.dest_mac)")
    println("  |- Type     : $(ethhdr.ptype)")
end # function display_ip_hdr

function display_ip_hdr(iphdr::IpHdr)
    println("IP Header")
    println("  |- Version         : $(iphdr.version)")
    println("  |- Length          : $(iphdr.length)")
    println("  |- Type of Service : $(iphdr.services)")
    println("  |- Total Length    : $(iphdr.totlen)")
    println("  |- ID              : $(iphdr.id)")
    println("  |- TTL             : $(iphdr.ttl)")
    println("  |- Protocol        : $(iphdr.protocol)")
    println("  |- Src Ip          : $(iphdr.src_ip)")
    println("  |- Dest Ip         : $(iphdr.dest_ip)")
    println("  |- Checksum        : 0x$(hex(iphdr.checksum,4))")
end # function display_ip_hdr

function display_udp_hdr(udphdr::UdpHdr)
    println("UDP Header")
    println("  |- Src Port  : $(udphdr.src_port)")
    println("  |- Dest Port : $(udphdr.dest_port)")
    println("  |- Length    : $(udphdr.length)")
    println("  |- Checksum  : 0x$(hex(udphdr.checksum, 4))")
    print("  |- Data : ")

    n = 0
    for byte = udphdr.data
        if n % 16 == 0 && n != 0
            print("\n            ")
        end
        print("$(hex(byte, 2)) ")
        n = n + 1
    end
end # function display_udp_hdr

cap     = PcapOffline("data/dns-query-response.pcap")
rec     = pcap_get_record(cap)
layers  = decode_pkt(rec.payload)

println("---------- UDP Packet ----------\n")
display_eth_hdr(layers.datalink)
display_ip_hdr(layers.network)
if (layers.network.protocol == 17)
    display_udp_hdr(layers.protocol)
end
println("\n\n--------------------------------\n")
```

###Output
```
---------- UDP Packet ----------

Ethernet Header
  |- Src Mac  : 74:de:2b:08:78:09
  |- Dest Mac : 00:24:fe:b1:8f:dc
  |- Type     : 2048
IP Header
  |- Version         : 4
  |- Length          : 20
  |- Type of Service : 0
  |- Total Length    : 63
  |- ID              : 20831
  |- TTL             : 64
  |- Protocol        : 17
  |- Src Ip          : 192.168.0.51
  |- Dest Ip         : 192.168.0.1
  |- Checksum        : 0x67ca
UDP Header
  |- Src Port  : 34904
  |- Dest Port : 53
  |- Length    : 43
  |- Checksum  : 0xa24a
  |- Data : 56 6d 01 00 00 01 00 00 00 00 00 00 0d 66 65 64
            6f 72 61 70 72 6f 6a 65 63 74 03 6f 72 67 00 00
            01 00 01

--------------------------------
```
