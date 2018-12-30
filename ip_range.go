package gscan

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mikioh/ipaddr"
)

func inet_ntoa(ipnr int64) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipnr & 0xFF)
	bytes[1] = byte((ipnr >> 8) & 0xFF)
	bytes[2] = byte((ipnr >> 16) & 0xFF)
	bytes[3] = byte((ipnr >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

func inet_aton(ipnr net.IP) int64 {
	bits := strings.Split(ipnr.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	return sum
}

type IPRange struct {
	StartIP int64
	EndIP   int64
}

func parseIPRange(start, end string) (*IPRange, error) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)

	if !strings.Contains(end, ".") {
		ss := strings.Split(start, ".")
		st := strings.Join(ss[0:3], ".")
		end = fmt.Sprintf("%s.%s", st, end)
		//		fmt.Printf("###%v  ", st)
		//		return nil, fmt.Errorf("Invalid IPRange %s-%s", start, end)
	}
	//fmt.Printf("##%s %s\n",start, end)
	si := net.ParseIP(start)
	ei := net.ParseIP(end)

	iprange := new(IPRange)
	iprange.StartIP = inet_aton(si)
	iprange.EndIP = inet_aton(ei)
	if iprange.StartIP > iprange.EndIP {
		return nil, fmt.Errorf("Invalid IPRange %s-%s", start, end)
	}
	return iprange, nil
}

func parseIPRangeFile(file string) ([]*IPRange, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ipranges := make([]*IPRange, 0)
	scanner := bufio.NewScanner(f)
	lineno := 1
	for scanner.Scan() {
		strline := scanner.Text()
		strline = strings.TrimSpace(strline)
		//comment start with '#'
		if strings.HasPrefix(strline, "#") || len(strline) == 0 {
			continue
		}
		var begin, end string
		if strings.Contains(strline, "-") && strings.Contains(strline, "/") {
			ss := strings.Split(strline, "-")
			if len(ss) == 2 {
				iprange1, iprange2 := ss[0], ss[1]
				// "1.9.22.0/24-1.9.22.0"
				if strings.Contains(iprange1, "/") && !strings.Contains(iprange2, "/") {
					begin = iprange1[:strings.Index(iprange1, "/")]
					if begin == iprange2 {
						iprange2 = iprange1
					}
				} else if strings.Contains(iprange2, "/") {
					// 1.9.22.0/24-1.9.22.0/24
					begin = iprange1[:strings.Index(iprange1, "/")]
				} else {
					// 1.9.22.0-1.9.23.0/24
					begin = iprange1
				}
				// c, err := ipaddr.Parse(begin + "," + iprange2)
				// if err != nil {
				// 	panic(err)
				// }
				// return ipaddr.Aggregate(c.List())

				if c, err := ipaddr.Parse(iprange2); err == nil {
					end = c.Last().IP.String()
				}
			}
		} else if strings.Contains(strline, "-") {
			num_regions := strings.Split(strline, ".")
			if len(num_regions) == 4 {
				// "xxx.xxx.xxx-xxx.xxx-xxx"
				for _, region := range num_regions {
					if strings.Contains(region, "-") {
						a := strings.Split(region, "-")
						s, e := a[0], a[1]
						begin += "." + s
						end += "." + e
					} else {
						begin += "." + region
						end += "." + region
					}
				}
				begin = begin[1:]
				end = end[1:]
			} else {
				// "xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx"
				a := strings.Split(strline, "-")
				begin, end = a[0], a[1]
				if 1 <= len(end) && len(end) <= 3 {
					prefix := begin[0:strings.LastIndex(begin, ".")]
					end = prefix + "." + end
				}
			}
		} else if strings.HasSuffix(strline, ".") {
			// "xxx.xxx.xxx."
			begin = strline + "0"
			end = strline + "255"
		} else if strings.Contains(strline, "/") {
			// "xxx.xxx.xxx.xxx/xx"
			ip, ipnet, err := net.ParseCIDR(strline)
			if nil != err {
				return nil, err
			}
			begin = ip.String()
			ones, _ := ipnet.Mask.Size()
			v := inet_aton(ip)
			var tmp uint32
			tmp = 0xFFFFFFFF
			tmp = tmp >> uint32(ones)
			v = v | int64(tmp)
			endip := inet_ntoa(v)
			end = endip.String()
		} else {
			// "xxx.xxx.xxx.xxx"
			begin = strline
			end = strline
		}

		iprange, err := parseIPRange(begin, end)
		if nil != err {
			return nil, fmt.Errorf("Invalid line:%d in IP Range file:%s", lineno, file)
		}
		ipranges = append(ipranges, iprange)
		lineno = lineno + 1
	}
	if len(ipranges) > 5 {
		dest := make([]*IPRange, len(ipranges))
		perm := rand.Perm(len(ipranges))
		for i, v := range perm {
			dest[v] = ipranges[i]
		}
		ipranges = dest
	}
	return ipranges, nil
}
