using BinDeps

@BinDeps.setup

jlcap = library_dependency("libjlcap")

@linux_only begin
    prefix = joinpath(BinDeps.depsdir(jlcap), "usr")
    pcapsrcdir = joinpath(BinDeps.depsdir(jlcap), "src", "jl-cap-lib")
    pcapbuilddir = joinpath(BinDeps.depsdir(jlcap), "builds", "jl-cap-lib")
    provides(BuildProcess,
            (@build_steps begin
                CreateDirectory(pcapbuilddir)
                CreateDirectory("$prefix/lib")
                CreateDirectory("$prefix/include")
                @build_steps begin
                    ChangeDirectory(pcapbuilddir)
                    FileRule(joinpath(prefix, "lib", "libjlcap.so"), @build_steps begin
                        `gcc -c -O -W -Wall -fpic -std=gnu99 $pcapsrcdir/jl-cap-lib.c -lpcap`
                        `gcc -shared -o libjlcap.so jl-cap-lib.o -lpcap`
                        `cp libjlcap.so $prefix/lib`
                        `cp $pcapsrcdir/jl-cap-lib.h $prefix/include`
                    end)
                end
            end), jlcap, os = :Linux)
end

@BinDeps.install Dict(:libjlcap => :libjlcap)
