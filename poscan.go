// tcp/udp?      port range?   proxy?    multithread?
// scan type(tcp, ping, syn, syn, ack, fin, null, xmas, rpc, udp, stealth scan)
// port range and it's type: 1. port rang like 1-100  2. single port like 22  3. specified ports like 22,80,443
// proxy command
// get elements from user in terminal: port type & port range type and port range & proxy list & if wanna use
// or not & scan type

package main


import (
	"fmt"
	"net"
	//"context"
	//"net/Dialer"
	"strconv" // strconv.Itoa is for converting int to string and strconv.Atoi is for converting string to int
	"time"
	"flag"
	"strings"
	"os"
	"golang.org/x/net/proxy"
	//"log"
)

type ScanResult struct {
	Port    string
	State   string
	Service string
}

func ScanTcp(hostname string, port string) ScanResult {
	result := ScanResult{Port: port + string("/tcp")}
	address := hostname + ":" + port
	conn, erri := net.DialTimeout("tcp", address, 60*time.Second)  // or use net.DialTimeout instead of Dial , 60*time.Second
	if erri != nil {
		result.State = "Closed"
		return result
	}
	defer conn.Close()  // defer is here to wait for previous return and delay the close
	// till previous function done what should it do
	result.State = "OPEN"
	return result
}

func ScanTcpp(hostname string, port string, poxy string) ScanResult {
	result := ScanResult{Port: port + string("/tcp")}
	address := hostname + ":" + port
	dialer, err := proxy.SOCKS5("tcp", poxy, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy connection error:", err)
		os.Exit(1)
	}
	conn, erri := dialer.Dial("tcp", address)  // or use net.DialTimeout instead of Dial , 60*time.Second
	//conn, erri := net.DialTimeout("tcp", address, 60*time.Second)  // or use net.DialTimeout instead of Dial , 60*time.Second
	if erri != nil {
		result.State = "Closed"
		return result
	}
	defer conn.Close()  // defer is here to wait for previous return and delay the close
	// till previous function done what should it do
	result.State = "OPEN"
	return result
}

// #QUES: scan in wireshark? yes, checked scan in wireshark and it works
// about udp packets
// as explained in detail, the connection is not closed at that point. 
// A normal closing of a connection doesn't happen until both sids send FIN-ACK(finish the connection).
// If you want to send more data then you may eventually get an RST and a broken pipe,
// but you can't somehow expect a synchronous error from your erroneous packets.
// https://stackoverflow.com/questions/51317968/write-on-a-closed-net-conn-but-returned-nil-error
func ScanUDP(host string, port int) ScanResult {
	pori := strconv.Itoa(port)
	result := ScanResult{Port: pori + string("/udp")}
	hosti := host+":"+pori
	serverAddr, err := net.ResolveUDPAddr("udp4", hosti)
	conn,erro := net.DialUDP("udp",nil,serverAddr)
	fmt.Println(conn)
	if erro != nil {
		result.State = "CLOSE"
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(time.Second * 1)))
	var data []byte
	switch serverAddr.Port {
	case 53:
		data = []byte("\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01")
	case 123:
		data = []byte("\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3")
	case 161:
		data = []byte("\x30\x2c\x02\x01\x00\x04\x07\x70\x75\x62\x6c\x69\x63\xA0\x1E\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0D\x2B\x06\x01\x04\x01\x94\x78\x01\x02\x07\x03\x02\x00\x05\x00")
	default:
		data = []byte("\xff\xff\x70\x69\x65\x73\x63\x61\x6e\x6e\x65\x72\x20\x2d\x20\x40\x5f\x78\x39\x30\x5f\x5f")
	} // write simple data to the channel
	_, err = conn.Write(data)
	if err != nil {
		result.State = "CLOSE"
		return result
	}
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	if err != nil {
		result.State = "CLOSE"
		return result
	}
	result.State = "OPEN"
	return result
}

// #QUES: live host no icmp?
// some firewalls like zone alarm, in windows firewall, close totally echo reply
// echo 1 >/proc/sys/net/ipv4/icmp_echo_ignore_all
// at all, we can set ignore icmp requests
// https://www.linuxhowtos.org/Security/disable_ping.htm
func ScanICMP(hostname string) ScanResult {
	result := ScanResult{Port: string("ping scan")}
	conn, err := net.Dial("ip4:icmp", hostname)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	var msg [512]byte
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4] = 0
	msg[5] = 13
	msg[6] = 0
	msg[7] = 37
	msg[8] = 99
	len := 9
	check := checkSum(msg[0:len])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 0xff)
	//fmt.Println(msg[0:len])
	for i := 0; i < 2; i++ {
		_, err = conn.Write(msg[0:len])
		if err != nil {
			//fmt.Println(err.Error())
			continue
		}
		conn.SetReadDeadline((time.Now().Add(time.Millisecond * 400)))
		_, err := conn.Read(msg[0:])
		if err != nil {
			//fmt.Println(err.Error())
			continue
		}
		//fmt.Println(msg[0 : 20+len])
		//fmt.Println("Got response")
		if msg[20+5] == 13 && msg[20+7] == 37 && msg[20+8] == 99 {
			result.State = "OPEN"
			return result
		}
	}
	result.State = "CLOSE"
	return result
}

func checkSum(msg []byte) uint16 {
	summ := 0
	len := len(msg)
	for i := 0; i < len-1; i += 2 {
		summ += int(msg[i])*256 + int(msg[i+1])
	}
	if len%2 == 1 {
		summ += int(msg[len-1]) * 256
	}
	summ = (summ >> 16) + (summ & 0xffff)
	summ += (summ >> 16)
	var answer uint16 = uint16(^summ)
	return answer
}

// nmap doesn't support socks5, nmap just uses proxy for tcp connect scan and
// other scans won't work over proxy,
// https://security.stackexchange.com/questions/120708/nmap-through-proxy
// so it seems that the best choice is to use external tools like proxychains
// also for udp scan, even proxychains won't work even in nmap
// maybe it's because it is socks5 proxy or it is tcp proxy
// i mean it opens tcp channel
// we should open a tcp channel then wrap the udp packet and send it over tcp stream
// (include tcp headers and send it as a data over tcp channel)
// to proxy, then unwrap data and then send it to udp target(this is udp associate)
// https://stackoverflow.com/questions/41967217/why-does-socks5-require-to-relay-udp-over-udp
// http://www.cs.columbia.edu/~lennox/udptunnel/
// When a client wants to relay UDP traffic over the SOCKS5 proxy, the client makes a UDP
// associate request over the TCP. SOCKS5 server then returns an available UDP port to the
// client to send UDP packages to.
// Client then starts sending the UDP packages that needs to be relayed to the new UDP port
// that is available on SOCKS5 server. SOCKS5 server redirects these UDP packages to the remote
// server and redirects the UDP packages coming from the remote server back to the client.
// When client wants to terminate the connection, it sends a FIN package over the TCP.
// The SOCKS5 server then terminates the UDP connection created for the client and then
// terminates the TCP connection.
func InitialScan(hostname string, scantype string, ssports string, poxy string) []ScanResult {

	var results []ScanResult
	if scantype == "udp" {
		poo,_ := strconv.Atoi(ssports)
		results = append(results, ScanUDP(hostname,poo))
	} else if scantype == "tcp" {
		if poxy != "" {
			results = append(results, ScanTcpp(hostname, ssports, poxy))
		} else {
			results = append(results, ScanTcp(hostname, ssports))
		}
	} else if scantype == "icmp" {
		results = append(results, ScanICMP(hostname))
	} /// should define more for syn, fin, stealth and etc
	return results
}

func main() {
	sports := flag.String("sports", "", "if you want to scan specified ports(more than one port), you have to specify ports and split them with ','")
	singlep := flag.String("oneport", "", "define one port to scan")
	portrange := flag.String("prange", "", "define port range - split the start and end port using '-'")
	scantype := flag.String("scantype", "", "define the scan type tcp, udp, icmp, syn, ack, fin, null, xmas, rpc, stealth")
	target := flag.String("target", "localhost", "define target ip address")
	poxy := flag.String("proxy", "", "define proxy - type:ip:port - JUST SUPPORTS SOCKS5 PROXY")
	flag.Parse()
	//
	if *portrange == "" && *sports == "" && *singlep != "" { // this means that we don't have range of ports, just specified ports
		scoutput := InitialScan(*target, *scantype, *singlep, *poxy)
		fmt.Println(scoutput[0])
	} else if *portrange != "" && *sports == "" && *singlep == "" {  // this means that we have port range and we should parse portrange value - split with '-'
		pranges := strings.Split(*portrange, "-")
		startport,_ := strconv.Atoi(pranges[0])  // int of start port
		endport,_ := strconv.Atoi(pranges[1])   // int of enf port
		for tport := startport; tport <= endport; tport++ {
			scp := strconv.Itoa(tport)
			scoutput := InitialScan(*target, *scantype, scp, *poxy)
			fmt.Println(scoutput[0])
		}
	} else if *portrange == "" && *sports != "" && *singlep == "" {
		sportsA := strings.Split(*sports, ",")
		for _,scport := range sportsA {
			scoutput := InitialScan(*target, *scantype, scport, *poxy)
			fmt.Println(scoutput[0])
		}
	} else {
		fmt.Println("\n  [!]CHECK YOUR PROVIDED COMMANDs[!]")
		fmt.Println("  YOU HAVE TO PROVIDE 'target' AND 'scantype'")
		fmt.Println("  FOR THE PORT DEFINITION, YOU HAVE TO PROVIDE ONE OF THREE OPTIONS YOU HAVE")
		fmt.Println("  'sports' FOR SPECIFIC PORTS THAT YOU WANT TO SPECIFY")
		fmt.Println("  'oneport' IF YOU WANT TO SCAN SINGLE PORT")
		fmt.Println("  'prange' IF YOU WANT TO PROVIDE PORT RANGE TO SCAN\n")
		flag.PrintDefaults()
	}
}
