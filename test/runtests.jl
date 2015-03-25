using Pcap
using Base.Test

# write your own tests here
#@test 1 == 1

println(pcap_lookupdev())
pcap_findalldevs()
