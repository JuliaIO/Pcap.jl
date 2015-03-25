export PcapFileHeader, PcapRec, PcapOffline,
       pcap_get_record

type PcapFileHeader
    magic_number::Uint32
    version_major::Uint16
    version_minor::Uint16
    thiszone::Int32
    sigfigs::Uint32
    snaplen::Uint32
    network::Uint32

    PcapFileHeader() = new(0,0,0,0,0,0,0)
end # type PcapFileHeader

type PcapRec
    ts_sec::Uint32
    ts_usec::Uint32
    incl_len::Uint32
    orig_len::Uint32
    payload::Array{Uint8}

    PcapRec() = new(0,0,0,0, Array(Uint8, 0))
end # type PcapRec

type PcapOffline
    filename::String
    file::IO
    filehdr::PcapFileHeader
    record::PcapRec
    hdr_read::Bool

    function PcapOffline(fn::String)
        filename = fn
        file     = open(fn, "r+")
        filehdr  = PcapFileHeader()
        record   = PcapRec()
        hdr_read = false
        new(filename, file, filehdr, record, hdr_read)
    end # constructor
end # type PcapOffline

function pcap_get_header(s::PcapOffline)
    filehdr = PcapFileHeader()
    filehdr.magic_number  = read(s.file, Uint32)
    filehdr.version_major = read(s.file, Uint16)
    filehdr.version_minor = read(s.file, Uint16)
    filehdr.thiszone      = read(s.file, Int32)
    filehdr.sigfigs       = read(s.file, Uint32)
    filehdr.snaplen       = read(s.file, Uint32)
    filehdr.network       = read(s.file, Uint32)
    s.filehdr  = filehdr
    s.hdr_read = true
end # function pcap_get_header

function pcap_get_record(s::PcapOffline)
    if (s.hdr_read != true)
        pcap_get_header(s)
    end

    rec = PcapRec()
    rec.ts_sec   = read(s.file, Uint32)
    rec.ts_usec  = read(s.file, Uint32)
    rec.incl_len = read(s.file, Uint32)
    rec.orig_len = read(s.file, Uint32)
    rec.payload  = readbytes(s.file, rec.incl_len)
    rec
end # function pcap_fopen_offline
