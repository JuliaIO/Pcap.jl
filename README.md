##Pcap [![Build Status](https://travis-ci/bearnado/Pcap.jl.svg?branch=master)](https://travis-ci.org/bearnado/PCap.jl)

Pcap contains libpcap bindings for Julia as well as logic to parse and extract useful data from packet captures

###Example
```julia
function display_eth_hdr(ethhdr::EthHdr)
    println("----- ETHERNET -----")
    println("Src Mac: $(ethhdr.src_mac)")
    println("Dst Mac: $(ethhdr.dest_mac)\n")
end # function display_ip_hdr

function display_ip_hdr(iphdr::IpHdr)
    println("----- IP -----")
    println("Version:  $(iphdr.version)")
    println("Src Ip:   $(iphdr.src_ip)")
    println("Dest Ip:  $(iphdr.dest_ip)")
    println("Checksum: 0x$(hex(iphdr.checksum,4))\n")
end # function display_ip_hdr

function display_tcp_hdr(tcphdr::TcpHdr)
    println("----- TCP -----")
    println("Src Port:  $(tcphdr.src_port)")
    println("Dest Port: $(tcphdr.dest_port)")
    println("Checksum:  0x$(hex(tcphdr.checksum, 4))\n")
end # function display_tcp_hdr

cap     = PcapOffline("capture.pcap")
rec     = pcap_get_record(cap)
layers  = decode_pkt(rec.payload)

display_eth_hdr(layers.datalink)
display_ip_hdr(layers.network)
if (layers.network.protocol == 6)
    display_tcp_hdr(layers.protocol)
end
```

###Output
```
[bearnado@fairyland test]$ julia demo.jl
----- ETHERNET -----
Src Mac: 30:46:9a:49:a6:da
Dst Mac: 0c:84:dc:85:62:99

----- IP -----
Version:  4
Src Ip:   192.101.102.2
Dest Ip:  192.168.1.8
Checksum: 0x02ef

----- TCP -----
Src Port:  80
Dest Port: 59222
Checksum:  0x7d2c
```
