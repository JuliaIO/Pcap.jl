export EthHdr, IpHdr, decode_eth_hdr, decode_ip_hdr

type EthHdr
    dest_mac::String
    src_mac::String
    ptype::Uint16
    EthHdr() = new("","",0)
end # type EthHdr

type IpHdr
    version::Uint8
    length::Uint8
    services::Uint8
    totlen::Uint16
    id::Uint16
    flags::BitArray
    frag_offset::Uint16
    ttl::Uint8
    protocol::Uint8
    checksum::Uint16
    src_ip::String
    dest_ip::String
    IpHdr() = new(0,0,0,0,0,BitArray(3),0,0,0,0,"","")
end # type IpHdr

function decode_eth_hdr(d::Array{Uint8})
    eh = EthHdr()
    # TODO: use map and specify 2 character hex
    eh.dest_mac = string(hex(d[1]), ":", hex(d[2]), ":", hex(d[3]), ":", hex(d[4]), ":", hex(d[5]), ":", hex(d[6]))
    eh.src_mac  = string(hex(d[7]), ":", hex(d[8]), ":", hex(d[9]), ":", hex(d[10]), ":", hex(d[11]), ":", hex(d[12]))
    eh.ptype    = reinterpret(Uint16, d[14:15])[1]
    eh
end # function decode_eth_hdr

function decode_ip_hdr(d::Array{Uint8})
    iph = IpHdr()
    # TODO: split version and length at 4 bits
    iph.version     = d[1]
    iph.length      = d[1]
    iph.services    = d[2]
    iph.totlen      = reinterpret(Uint16, d[3:4])[1]
    iph.id          = reinterpret(Uint16, d[5:6])[1]
    iph.flags[1]    = (d[7] & (1 << 7)) > 0
    iph.flags[2]    = (d[7] & (1 << 6)) > 0
    iph.flags[3]    = (d[7] & (1 << 5)) > 0
    iph.frag_offset = reinterpret(Uint16, d[7:8])[1] & 0x7ff
    iph.ttl         = d[9]
    iph.protocol    = d[10]
    iph.checksum    = reinterpret(Uint16, d[11:12])[1]
    # TODO change to maps
    iph.src_ip      = string(Int(d[13]), ".", Int(d[14]), ".", Int(d[15]), ".", Int(d[16]))
    iph.dest_ip     = string(Int(d[17]), ".", Int(d[18]), ".", Int(d[19]), ".", Int(d[20]))
    iph
end # function decode_ip_hdr
