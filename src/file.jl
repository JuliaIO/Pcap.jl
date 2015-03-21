export PcapFileHeader

immutable PcapFileHeader
    magic::Uint32
    version_major::Uint16
    version_minor::Uint16
    thiszone::Int32
    sigfigs::Uint32
    snaplen::Uint32
    linktype::Uint32
end # type pcap_file_header

