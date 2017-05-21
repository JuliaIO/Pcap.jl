using Compat
import Compat.read

export PcapFileHeader, PcapRec, PcapOffline,
       pcap_get_record

type PcapFileHeader
    magic_number::UInt32
    version_major::UInt16
    version_minor::UInt16
    thiszone::Int32
    sigfigs::UInt32
    snaplen::UInt32
    network::UInt32
    PcapFileHeader() = new(0,0,0,0,0,0,0)
end # type PcapFileHeader

type PcapRec
    ts_sec::UInt32
    ts_usec::UInt32
    incl_len::UInt32
    orig_len::UInt32
    payload::Vector{UInt8}
    PcapRec() = new(0,0,0,0, Vector{UInt8}(0))
end # type PcapRec

type PcapOffline
    filename::AbstractString
    file::IO
    filehdr::PcapFileHeader
    record::PcapRec
    is_big::Bool
    function PcapOffline(fn::AbstractString)
        filename = fn
        file = open(fn, "r+")
        filehdr, is_big = decode_hdr(file)
        record = PcapRec()
        new(filename, file, filehdr, record, is_big)
    end # constructor
end # type PcapOffline

#----------
# decode PCap file format header
#----------
function decode_hdr(file::Any)
    filehdr = PcapFileHeader()
    filehdr.magic_number  = read(file, UInt32)
    big_endian = false
    if filehdr.magic_number == 0xd4c3b2a1
        big_endian = true
    end
    filehdr.version_major = big_endian ? ntoh(read(file, UInt16)) : read(file, UInt16)
    filehdr.version_minor = big_endian ? ntoh(read(file, UInt16)) : read(file, UInt16)
    filehdr.thiszone      = read(file, Int32)
    filehdr.sigfigs       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)
    filehdr.snaplen       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)
    filehdr.network       = big_endian ? ntoh(read(file, UInt32)) : read(file, UInt32)
    return [filehdr, big_endian]
end # function decode_hdr

#----------
# decode next record in PCap file
#----------
function pcap_get_record(s::PcapOffline)
    rec = PcapRec()
    if (!eof(s.file))
        rec.ts_sec   = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        rec.ts_usec  = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        rec.incl_len = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        rec.orig_len = s.is_big ? ntoh(read(s.file, UInt32)) : read(s.file, UInt32)
        rec.payload  = read(s.file, rec.incl_len)
        return rec
    end
    nothing
end # function pcap_get_record
