using Pcap
using Documenter

DocMeta.setdocmeta!(Pcap, :DocTestSetup, :(using Pcap); recursive=true)

makedocs(;
    modules=[Pcap],
    authors="Pcap.jl contributors",
    repo="https://github.com/JuliaIO/Pcap.jl/blob/{commit}{path}#{line}",
    sitename="Pcap.jl",
    format=Documenter.HTML(;
        prettyurls=get(ENV, "CI", "false") == "true",
        canonical="https://JuliaIO.github.io/Pcap.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/JuliaIO/Pcap.jl",
    devbranch="main",
)
