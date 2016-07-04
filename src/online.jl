export cap_open_live, cap_set_filter, cap_close,
    cap_loop

if isfile(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
    include("../deps/deps.jl")
else
    error("Pcap not properly installed. Please run Pkg.build(\"Pcap\")")
end

function cap_open_live(device::AbstractString, snaplen::Int, promisc::Int, ms::Int)
    ccall((:_cap_open_live, Pcap.libjlcap), Int32, (Ptr{UInt8}, Int32, Int32, Int32), device, snaplen, promisc, ms)
end

function cap_set_filter(filter::AbstractString)
    ccall((:_cap_set_filter, Pcap.libjlcap), Int32, (Ptr{UInt8},), filter)
end

function cap_close()
    ccall((:_cap_close, Pcap.libjlcap), Void, ())
end

function cap_loop(count::Int)
    ccall((:_cap_loop, Pcap.libjlcap), Int32, (Int32,), count)
end
