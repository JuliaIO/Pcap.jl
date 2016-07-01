import GetC.@getCFun

if isfile(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
    include("../deps/deps.jl")
else
    error("Pcap not properly installed. Please run Pkg.build(\"Pcap\")")
end

const pcaplib = "libjlpcap"

@getCFun pcaplib pcap_open_live capture_open_live(
    device::Ptr{UInt8}, snaplen::Int32, promisc::Int32, ms::Int32
)::Int32
export pcap_open_live

@getCFun pcaplib pcap_set_filter capture_set_filter(filter::Ptr{UInt8})::Int32
export pcap_set_filter

@getCFun pcaplib pcap_close capture_close()::Void
export pcap_close

@getCFun pcaplib pcap_loop capture_loop()::Int32
export pcap_loop



