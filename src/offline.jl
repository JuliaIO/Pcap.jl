export PcapFileHeader, PcapRec, PcapOffline,
       pcap_get_record

struct PcapFileHeader
    magic_number::UInt32
    version_major::UInt16
    version_minor::UInt16
    thiszone::Int32
    sigfigs::UInt32
    snaplen::UInt32
    network::UInt32
end # struct PcapFileHeader

struct PcapRec
    ts_sec::UInt32
    ts_usec::UInt32
    incl_len::UInt32
    orig_len::UInt32
    payload::Vector{UInt8}
end # struct PcapRec

struct PcapOffline
    filename::AbstractString
    file::IO
    filehdr::PcapFileHeader
    is_big::Bool
    function PcapOffline(fn::AbstractString)
        filename = fn
        file = open(fn, "r+")
        filehdr, is_big = decode_hdr(file)
        new(filename, file, filehdr, is_big)
    end # constructor
end # struct PcapOffline

#----------
# decode PCap file format header
#----------
function decode_hdr(file::Any)
    magic_number = read(file, UInt32)
    big_endian = false
    if magic_number == 0xd4c3b2a1
        big_endian = true
    end
    version_major = big_endian ? ntoh(read(file, UInt16)) : read(file, UInt16)
    version_minor = big_endian ? ntoh(read(file, UInt16)) : read(file, UInt16)
    thiszone      = read(file, Int32)
    sigfigs       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)
    snaplen       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)
    network       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)

    filehdr = PcapFileHeader(magic_number, version_major, version_minor,
                             thiszone, sigfigs, snaplen, network)
    return [filehdr, big_endian]
end # function decode_hdr

#----------
# decode next record in PCap file
#----------
function pcap_get_record(s::PcapOffline)
    if (!eof(s.file))
        ts_sec   = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        ts_usec  = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        incl_len = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        orig_len = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        payload  = read(s.file, incl_len)

        return PcapRec(ts_sec, ts_usec, incl_len, orig_len, payload)
    end
    nothing
end # function pcap_get_record
