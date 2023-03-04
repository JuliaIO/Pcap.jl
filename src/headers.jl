export EthHdr, IpFlags, IpHdr,
       UdpHdr, TcpFlags, TcpHdr,
       IcmpHdr, DecPkt, decode_pkt

struct EthHdr
    dest_mac::AbstractString
    src_mac::AbstractString
    ptype::UInt16
end # struct EthHdr

struct IpFlags
    reserved::Bool
    dont_frag::Bool
    more_frags::Bool
end # struct IpFlags

struct IpHdr
    version::UInt8
    length::UInt8
    services::UInt8
    totlen::UInt16
    id::UInt16
    flags::IpFlags
    frag_offset::UInt16
    ttl::UInt8
    protocol::UInt8
    checksum::Bool
    src_ip::AbstractString
    dest_ip::AbstractString
end # struct IpHdr

struct TcpFlags
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
end # struct TcpFlags

struct TcpHdr
    src_port::UInt16
    dest_port::UInt16
    seq::UInt32
    ack::UInt32
    offset::UInt8
    flags::TcpFlags
    window::UInt16
    checksum::UInt16
    uptr::UInt16
    data::Vector{UInt8}
end # struct TcpHdr

struct UdpHdr
    src_port::UInt16
    dest_port::UInt16
    length::UInt16
    checksum::UInt16
    data::Vector{UInt8}
end # struct UdpHdr

struct IcmpHdr
    ptype::UInt8
    code::UInt8
    checksum::UInt16
    identifier::UInt16
    seqno::UInt16
end # struct IcmpHdr

struct DecPkt
    datalink::EthHdr
    network::IpHdr
    protocol::Any
end # struct DecPkt

@inline function getindex_he(::Type{T}, b::Vector{UInt8}, i) where T
    @boundscheck checkbounds(b, i + sizeof(T) - 1)
    return unsafe_load(Ptr{T}(pointer(b, i)))
end

@inline getindex_be(::Type{T}, b::Vector{UInt8}, i) where T = hton(getindex_he(T, b, i))

@inline hex(n, pad) = string(n, base=16, pad=pad)

#----------
# decode ethernet header
#----------
function decode_eth_hdr(d::Array{UInt8})
    dest_mac = string(hex(d[1], 2), ":", hex(d[2], 2), ":", hex(d[3], 2), ":",
                      hex(d[4], 2), ":", hex(d[5], 2), ":", hex(d[6], 2))
    src_mac  = string(hex(d[7], 2), ":", hex(d[8], 2), ":", hex(d[9], 2), ":",
                      hex(d[10], 2), ":", hex(d[11], 2), ":", hex(d[12], 2))
    ptype    = getindex_be(UInt16, d, 13)

    EthHdr(dest_mac, src_mac, ptype)
end # function decode_eth_hdr

#----------
# calculate IP checksum
#----------
function ip_checksum(buf::Array{UInt8})
    sum::UInt64 = 0
    for i in 1:2:length(buf)
        pair = getindex_he(UInt16, buf, i)
        sum += pair
        if (sum & 0x80000000) != 0
            sum = (sum & 0xFFFF) + (sum >> 16)
        end
    end

    while ((sum >> 16) != 0)
        sum = (sum & 0xFFFF) + (sum >> 16)
    end
    ~sum
end # function ip_checksum

#----------
# decode IP header
#----------
function decode_ip_hdr(d::Array{UInt8})
    version     = (d[1] & 0xf0) >> 4
    length      = (d[1] & 0x0f) * 4
    if ip_checksum(d[1:length]) == 0xFFFFFFFFFFFF0000
        checksum = true
    end
    services    = d[2]
    totlen      = getindex_be(UInt16, d, 3)
    id          = getindex_be(UInt16, d, 5)

    # set flags
    reserved   = (d[7] & (1 << 7)) > 0
    dont_frag  = (d[7] & (1 << 6)) > 0
    more_frags = (d[7] & (1 << 5)) > 0
    flags = IpFlags(reserved, dont_frag, more_frags)

    frag_offset = getindex_be(UInt16, d, 7) & 0x7ff
    ttl         = d[9]
    protocol    = d[10]
    src_ip      = string(Int(d[13]), ".", Int(d[14]), ".", Int(d[15]), ".", Int(d[16]))
    dest_ip     = string(Int(d[17]), ".", Int(d[18]), ".", Int(d[19]), ".", Int(d[20]))

    IpHdr(version, length, services, totlen, id, flags,
          frag_offset, ttl, protocol, checksum, src_ip, dest_ip)
end # function decode_ip_hdr

#----------
# decode TCP header
#----------
function decode_tcp_hdr(d::Array{UInt8})
    src_port  = getindex_be(UInt16, d, 1)
    dest_port = getindex_be(UInt16, d, 3)
    seq       = getindex_be(UInt32, d, 5)
    ack       = getindex_be(UInt32, d, 9)
    offset    = (d[13] & 0xf0) >> 4

    # set flags
    reserved = ((d[13] & 0x0e) >> 1) > 0
    nonce    = (d[13] & 1) > 0
    cwr      = (d[14] & (1 << 7)) > 0
    ecn      = (d[14] & (1 << 6)) > 0
    urgent   = (d[14] & (1 << 5)) > 0
    ack      = (d[14] & (1 << 4)) > 0
    push     = (d[14] & (1 << 3)) > 0
    reset    = (d[14] & (1 << 2)) > 0
    syn      = (d[14] & (1 << 1)) > 0
    fin      = (d[14] & 1) > 0
    flags = TcpFlags(reserved, nonce, cwr, ecn, urgent, ack, push, reset, syn, fin)

    window    = getindex_be(UInt16, d, 15)
    checksum  = getindex_be(UInt16, d, 17)
    uptr      = getindex_be(UInt16, d, 19)
    data      = d[offset * 4 + 1:end]
    

    TcpHdr(src_port, dest_port, seq, ack, offset, flags, window, checksum, uptr, data)
end # function decode_tcp_hdr

#----------
# decode UDP header
#----------
function decode_udp_hdr(d::Array{UInt8})
    src_port  = getindex_be(UInt16, d, 1)
    dest_port = getindex_be(UInt16, d, 3)
    length    = getindex_be(UInt16, d, 5)
    checksum  = getindex_be(UInt16, d, 7)
    data      = d[9:end]

    UdpHdr(src_port, dest_port, length, checksum, data)
end # function decode_udp_hdr

#----------
# decode ICMP header
#----------
function decode_icmp_hdr(d::Array{UInt8})
    ptype      = d[1]
    code       = d[2]
    checksum   = getindex_be(UInt16, d, 3)
    identifier = getindex_be(UInt16, d, 5)
    seqno      = getindex_be(UInt16, d, 7)

    IcmpHdr(ptype, code, checksum, identifier, seqno)
end # function decode_icmp_hdr

#----------
# decode ethernet packet
#----------
function decode_pkt(pkt::Array{UInt8})
    datalink  = decode_eth_hdr(pkt)
    iphdr     = decode_ip_hdr(pkt[15:end])

    protocol = nothing
    if (iphdr.protocol == 1)
        protocol = decode_icmp_hdr(pkt[15 + iphdr.length:end])
    elseif (iphdr.protocol == 6)
        protocol = decode_tcp_hdr(pkt[15 + iphdr.length:end])
    elseif (iphdr.protocol == 17)
        protocol = decode_udp_hdr(pkt[15 + iphdr.length:end])
    end

    DecPkt(datalink, iphdr, protocol)
end # function decode_pkt

