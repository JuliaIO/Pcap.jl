using Pcap
using Base.Test

# write your own tests here
#@test 1 == 1

#println(pcap_lookupdev())
#pcap_findalldevs()

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
