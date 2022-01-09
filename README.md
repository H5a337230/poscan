# poscan
" poscan " is a Port Scanner Written in GO 

At this stage, " poscan " supports tcp/udp/icmp(ping) scans and also scan through socks5 proxy(only socks5 and only for tcp scan) with ' -proxy ' command

The most important difference between " poscan " and other golang port scanners is that unlike the most of port scanners written in go that are not reliable in udp scan, " poscan " is mostly reliable and i tried to implement the udp scan as reliable and simple as possible



### TODO:
- [ ] Add UDP proxy support
- [ ] Include more type of scans like syn, fin, stealth, xmas, rpc, ack
- [ ] Multithread
- [x] _
