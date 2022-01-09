# poscan
" poscan " is a Port Scanner Written in GO 

At this stage, " poscan " supports tcp/udp/icmp(ping) scans and also scan through socks5 proxy(only socks5 and only for tcp scan) with ' -proxy ' command

The most important difference between " poscan " and other golang port scanners is that unlike the most of port scanners written in go that are not reliable in udp scan, " poscan " is mostly reliable and i tried to implement the udp scan as reliable and simple as possible


###### Example usage:

- tcp with proxy:
```bash
go run poscan.go -target 8.8.8.8 -oneport 994 -scantype tcp -proxy 127.0.0.1:9150
```

- tcp without proxy:
```bash
go run poscan.go -target 8.8.8.8 -oneport 994 -scantype tcp
go run poscan.go -target 8.8.8.8 -prange 21-25 -scantype tcp
go run poscan.go -target 8.8.8.8 -sports 21,25 -scantype tcp
```
- udp:
```bash
go run poscan.go -target 8.8.8.8 -sports 53,80 -scantype udp
```
- icmp: Remember that for ICMP scan you should run script with sudo
```bash
sudo go run poscan.go -target 8.8.8.8 -scantype icmp
```



### TODO:
- [ ] Add UDP proxy support
- [ ] Include more type of scans like syn, fin, stealth, xmas, rpc, ack
- [ ] Multithread
- [x] _
