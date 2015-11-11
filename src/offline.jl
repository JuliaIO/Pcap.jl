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
    payload::Array{UInt8}
    PcapRec() = new(0,0,0,0, Array(UInt8, 0))
end # type PcapRec

type PcapOffline
    filename::AbstractString
    file::IO
    filehdr::PcapFileHeader
    record::PcapRec
    hdr_read::Bool

    function PcapOffline(fn::AbstractString)
        filename = fn
        file     = open(fn, "r+")
        filehdr  = PcapFileHeader()
        record   = PcapRec()
        hdr_read = false
        new(filename, file, filehdr, record, hdr_read)
    end # constructor
end # type PcapOffline

#----------
# decode PCap file format header
#----------
function pcap_get_header(s::PcapOffline)
    filehdr = PcapFileHeader()
    filehdr.magic_number  = read(s.file, UInt32)
    filehdr.version_major = read(s.file, UInt16)
    filehdr.version_minor = read(s.file, UInt16)
    filehdr.thiszone      = read(s.file, Int32)
    filehdr.sigfigs       = read(s.file, UInt32)
    filehdr.snaplen       = read(s.file, UInt32)
    filehdr.network       = read(s.file, UInt32)
    s.filehdr  = filehdr
    s.hdr_read = true
end # function pcap_get_header

#----------
# decode next record in PCap file
#----------
function pcap_get_record(s::PcapOffline)
    if (s.hdr_read != true)
        pcap_get_header(s)
    end

    rec = PcapRec()

    if (!eof(s.file))
        rec.ts_sec   = read(s.file, UInt32)
        rec.ts_usec  = read(s.file, UInt32)
        rec.incl_len = read(s.file, UInt32)
        rec.orig_len = read(s.file, UInt32)
        rec.payload  = readbytes(s.file, rec.incl_len)
        return rec
    end

    nothing
end # function pcap_get_record
