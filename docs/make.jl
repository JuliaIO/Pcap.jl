using MakiePango
using Documenter

DocMeta.setdocmeta!(MakiePango, :DocTestSetup, :(using MakiePango); recursive=true)

makedocs(;
    modules=[MakiePango],
    authors="Anshul Singhvi <anshulsinghvi@gmail.com> and contributors",
    repo="https://github.com/MakieOrg/MakiePango.jl/blob/{commit}{path}#{line}",
    sitename="MakiePango.jl",
    format=Documenter.HTML(;
        prettyurls=get(ENV, "CI", "false") == "true",
        canonical="https://MakieOrg.github.io/MakiePango.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/MakieOrg/MakiePango.jl",
    devbranch="main",
)
