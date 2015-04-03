export EthHdr, IpFlags, IpHdr,
       UdpHdr, TcpFlags, TcpHdr,
       decode_eth, decode_ip, decode_tcp,
       decode_udp

type EthHdr
    dest_mac::String
    src_mac::String
    ptype::Uint16
    EthHdr() = new("","",0)
end # type EthHdr

type IpFlags
    reserved::Bool
    dont_frag::Bool
    more_frags::Bool
    IpFlags() = new(false,false,false)
end # type IpFlags

type IpHdr
    version::Uint8
    length::Uint8
    services::Uint8
    totlen::Uint16
    id::Uint16
    flags::IpFlags
    frag_offset::Uint16
    ttl::Uint8
    protocol::Uint8
    checksum::Uint16
    src_ip::String
    dest_ip::String
    IpHdr() = new(0,0,0,0,0,IpFlags(),0,0,0,0,"","")
end # type IpHdr

type TcpFlags
    reserved::Bool
    nonce::Bool
    cwr::Bool
    ecn::Bool
    urgent::Bool
    ack::Bool
    push::Bool
    reset::Bool
    syn::Bool
    fin::Bool
    TcpFlags() = new(false,false,false,false,false,
                     false,false,false,false,false)
end # type TcpFlags

type TcpHdr
    src_port::Uint16
    dest_port::Uint16
    seq::Uint32
    ack::Uint32
    offset::Uint8
    flags::TcpFlags
    window::Uint16
    checksum::Uint16
    uptr::Uint16
    data::Array{Uint8}
    TcpHdr() = new(0,0,0,0,0,TcpFlags(),0,0,0, Array(Uint8))
end # type TcpHdr

type UdpHdr
    src_port::Uint16
    dest_port::Uint16
    length::Uint16
    checksum::Uint16
    data::Array{Uint8}
    UdpHdr() = new(0,0,0,0,Array{Uint8})
end # type UdpHdr

function decode_eth(d::Array{Uint8})
    eh = EthHdr()
    eh.dest_mac = string(hex(d[1], 2), ":", hex(d[2], 2), ":", hex(d[3], 2), ":",
                         hex(d[4], 2), ":", hex(d[5], 2), ":", hex(d[6], 2))
    eh.src_mac  = string(hex(d[7], 2), ":", hex(d[8], 2), ":", hex(d[9], 2), ":",
                         hex(d[10], 2), ":", hex(d[11], 2), ":", hex(d[12], 2))
    eh.ptype    = ntoh(reinterpret(Uint16, d[13:14])[1])
    eh
end # function decode_eth

function decode_ip(d::Array{Uint8})
    iph = IpHdr()
    iph.version     = (d[1] & 0xf0) >> 4
    iph.length      = d[1] & 0x0f
    iph.services    = d[2]
    iph.totlen      = ntoh(reinterpret(Uint16, d[3:4])[1])
    iph.id          = ntoh(reinterpret(Uint16, d[5:6])[1])

    # set flags
    flags = IpFlags()
    flags.reserved   = (d[7] & (1 << 7)) > 0
    flags.dont_frag  = (d[7] & (1 << 6)) > 0
    flags.more_frags = (d[7] & (1 << 5)) > 0
    iph.flags        = flags
    
    iph.frag_offset = ntoh(reinterpret(Uint16, d[7:8])[1] & 0x7ff)
    iph.ttl         = d[9]
    iph.protocol    = d[10]
    iph.checksum    = ntoh(reinterpret(Uint16, d[11:12])[1])
    iph.src_ip      = string(Int(d[13]), ".", Int(d[14]), ".", Int(d[15]), ".", Int(d[16]))
    iph.dest_ip     = string(Int(d[17]), ".", Int(d[18]), ".", Int(d[19]), ".", Int(d[20]))
    iph
end # function decode_ip

function decode_tcp(d::Array{Uint8})
    tcph = TcpHdr()
    tcph.src_port  = ntoh(reinterpret(Uint16, d[1:2])[1])
    tcph.dest_port = ntoh(reinterpret(Uint16, d[3:4])[1])
    tcph.seq       = ntoh(reinterpret(Uint32, d[5:8])[1])
    tcph.ack       = ntoh(reinterpret(Uint32, d[9:12])[1])
    tcph.offset    = (d[13] & 0xf0) >> 4

    # set flags
    flags = TcpFlags()
    flags.reserved = ((d[13] & 0x0e) >> 1) > 0
    flags.nonce    = (d[13] & 1) > 0
    flags.cwr      = (d[14] & (1 << 7)) > 0
    flags.ecn      = (d[14] & (1 << 6)) > 0
    flags.urgent   = (d[14] & (1 << 5)) > 0
    flags.ack      = (d[14] & (1 << 4)) > 0
    flags.push     = (d[14] & (1 << 3)) > 0
    flags.reset    = (d[14] & (1 << 2)) > 0
    flags.syn      = (d[14] & (1 << 1)) > 0
    flags.fin      = (d[14] & 1) > 0
    tcph.flags     = flags
    
    tcph.window    = ntoh(reinterpret(Uint16, d[15:16])[1])
    tcph.checksum  = ntoh(reinterpret(Uint16, d[17:18])[1])
    tcph.uptr      = ntoh(reinterpret(Uint16, d[19:20])[1])
    tcph.data      = d[tcph.offset * 4 + 1:end]
    tcph
end # function decode_tcp

function decode_udp(d::Array{Uint8})
    udph = UdpHdr()
    udph.src_port  = ntoh(reinterpret(Uint16, d[1:2])[1])
    udph.dest_port = ntoh(reinterpret(Uint16, d[3:4])[1])
    udph.length    = ntoh(reinterpret(Uint16, d[5:6])[1])
    udph.checksum  = ntoh(reinterpret(Uint16, d[7:8])[1])
    udph.data      = d[9:end]
    udph
end # function decode_udp
