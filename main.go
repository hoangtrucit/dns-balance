// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reflect is a small name server which sends back the IP address of its client, the
// recursive resolver.
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
//
// Basic use pattern:
//
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
//
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
//
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"
	"github.com/miekg/dns"
	"crypto/rsa"
	"io/ioutil"
	"github.com/tidwall/gjson"
	"errors"
	"math/rand"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"strconv"
)

type TypeRecordA struct{
	Name string
	Ip string
	Ttl int
}


var ConfigDomain map[string]string
var QueryJson gjson.Result
var ListDomains = make(map[string]string)

func RandomWeightedSelect(ips []gjson.Result, totalWeight int) (gjson.Result, error) {
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(totalWeight)
	for _, g := range ips {
		r -= int(g.Get("weight").Int())
		if r <= 0 {
			return g, nil
		}
	}
	return gjson.Result{}, errors.New("No game selected")
}

func QueryRecordA(domain string,alias string) (TypeRecordA , error){
	aliasM := ""
	if alias == "" {
		aliasM = "www"
	}else{
		aliasM = alias
	}
	fmt.Println("records.A." + aliasM)
	result := gjson.Get(ConfigDomain[domain],"records.A." + aliasM )

	if result.Exists(){
		listIps := result.Get("ips")
		var _t TypeRecordA
		var err error
		var realIp gjson.Result
		if listIps.Exists(){
			realIp, err = RandomWeightedSelect(listIps.Array(),int(result.Get("total").Int()))
		}else{
			err = nil
			realIp = result
		}
		if err == nil{
			if alias == ""{
				_t.Name = domain
			}else{
				_t.Name = alias + "." + domain
			}
			_t.Ip = realIp.Get("ip").String()
			_t.Ttl = int(result.Get("ttl").Int())
			return _t, nil
		}
	}
	return TypeRecordA{} , errors.New("no ip selected")
}

func QueryRecordTXT(domain string,alias string) ([]gjson.Result , error){
	if alias == "" {
		alias = domain
	}
	result := gjson.Get(ConfigDomain[domain],"records.TXT." + alias )
	if result.Exists(){
		return result.Array(), nil
	}
	return nil , errors.New("no ip selected")
}

func QueryRecordCNAME(domain string,alias string) (gjson.Result , error){
	result := gjson.Get(ConfigDomain[domain],"records.CNAME." + alias )
	if result.Exists(){
		return result, nil
	}
	return gjson.Result{} , errors.New("no ip selected")
}

func QueryRecordCMX(domain string,alias string) ([]gjson.Result , error){
	result := gjson.Get(ConfigDomain[domain],"records.MX" )
	if result.Exists(){
		return result.Array(), nil
	}
	return []gjson.Result{} , errors.New("no ip selected")
}


func LoadFileDo(){
	ConfigDomain = make(map[string]string)
	for _,val := range ListDomains{
		file, err := ioutil.ReadFile("./data/"+string(val)+".json")
		if err == nil {
			ConfigDomain[string(val)] = string(file)
		}
	}
}

func ValidDomain(s string) (string,string,error){
	s = strings.TrimSuffix(s,".")
	result , err := publicsuffix.Parse(s)
	if  err == nil{
		domain := result.SLD +"."+ result.TLD
		domain = ListDomains[domain]
		suffix := result.TRD
		return domain, suffix, nil
	}
	return "","",errors.New("domain invalid")
}

func init(){
	ListDomains["tructh.xyz"] = "tructh.xyz"
	LoadFileDo()
}

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	printf     = flag.Bool("print", false, "print replies")
	compress   = flag.Bool("compress", false, "compress replies")
	tsig       = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
)

const dom = "whoami.miek.nl."

func getKeySign(m *dns.Msg) {
	pubkey, _ := dns.ReadRR(strings.NewReader(`tructh.dev. IN DNSKEY 257 3 7 AwEAAdS7Z7WxNcL/fGSU+34/PnV4WszCJbm+wIHmBslF4RQm6noOtaA8 cE1/aF23sakCHDtvMYsSh+z0Un/xU4+ahnhwIj9PtPm6wA4AFAS7/mG/ cu4HgENsYUPsukBsOjyfvs34OnKL+/NppymsBxRzG8I9uilovETQZLfN rR2sWc9P1Jj+ZWCjICQFnDLYtthGuKc913T8ttjJtxhuhWs9WMaAcMqS F6wq1Ox8QbJm6hPCESMnxEfZ59SDKAN0bZvLDCUasqNvsMIlaqCn66gK fB26WjQ9lFdIjBCiXZEJ8Nox2dSyQmbWnA/lzlIGOL7i4MZmEI0l37GC 8huTy9dTPGYDwfHISyYKxEfBcJjJDtw/HrFdr7uzpwfNl9TV7/v940FW WtQLQqOySjZVb2OtbWZB+zf8zM9gKtbgCU9F6elgBD5HgYFw0/50dZif Xwsvnb5BWC3lv7mxWdaEF3mg5q392IQVRHyZ3ZtcjGFAc8Yfr3Wz6tOw mR3x2+hTIl9uNi4ngT8vmCQERL3kKLRM916k+wXcBXdedWmIwzRWESTj ohxVyNR+sBr6JUKNvvWPEu+L0bVnlgY1prMH2l5zww7l/uuJan87UEyx 0v/Tw9Xt970TfgmTu2KoRON1JQNavRNR+H/KMowls3oYh/jd0oiCy3mb NDlHsohBl25SBFwX`), "./keys/Ktructh.dev.+007+31758.key")

	privStr := `Private-key-format: v1.3
Algorithm: 7 (NSEC3RSASHA1)
Modulus: 1LtntbE1wv98ZJT7fj8+dXhazMIlub7AgeYGyUXhFCbqeg61oDxwTX9oXbexqQIcO28xixKH7PRSf/FTj5qGeHAiP0+0+brADgAUBLv+Yb9y7geAQ2xhQ+y6QGw6PJ++zfg6cov782mnKawHFHMbwj26KWi8RNBkt82tHaxZz0/UmP5lYKMgJAWcMti22Ea4pz3XdPy22Mm3GG6Faz1YxoBwypIXrCrU7HxBsmbqE8IRIyfER9nn1IMoA3Rtm8sMJRqyo2+wwiVqoKfrqAp8HbpaND2UV0iMEKJdkQnw2jHZ1LJCZtacD+XOUgY4vuLgxmYQjSXfsYLyG5PL11M8ZgPB8chLJgrER8FwmMkO3D8esV2vu7OnB82X1NXv+/3jQVZa1AtCo7JKNlVvY61tZkH7N/zMz2Aq1uAJT0Xp6WAEPkeBgXDT/nR1mJ9fCy+dvkFYLeW/ubFZ1oQXeaDmrf3YhBVEfJndm1yMYUBzxh+vdbPq07CZHfHb6FMiX242LieBPy+YJAREveQotEz3XqT7BdwFd151aYjDNFYRJOOiHFXI1H6wGvolQo2+9Y8S74vRtWeWBjWmswfaXnPDDuX+64lqfztQTLHS/9PD1e33vRN+CZO7YqhE43UlA1q9E1H4f8oyjCWzehiH+N3SiILLeZs0OUeyiEGXblIEXBc=
PublicExponent: AQAB
PrivateExponent: SCHbgqI6Boq21SwnMqGjPhW3RCK4xAjIIcOrnWfScBDaBNUkBNc5hS2kZ9K3rQUIKacEd5GrAU+/AZ8EpHbTDdeH5UvTo7INGTIxl4FfOim+gLOObE49lNiaNun7vT61ZgW7W8fXgKvcgKbSJ774NJ7VluDqpbK71A8rmhoswbzh65anLWNirJQyaJNPPHqOdjbj7cka/ts2+FPRbZF5nqVCmY179Wb4l89yP1niGRz+zprXVT2v/EEUukcqO19YGOS6mexvVQV26E7H+0zC1RmxKHGQ8R+qTqGfdGSYhIPOxu5C0bgHZuSXVvzBFQi9Csjk59dlyD0MdwlgXvzcR2S3tAWaRrZ1JHhkZLBc407xUaH7UGf4mrx5yX81FOSx9X/y2o/DO9qz+44wiaM9H9jDjOMdGYzgbhacgmHMIt0+q//tkXxGD1zNDQtzP5FmNgp30AVMIjfypa2/zsVszArfo5g1MnS62K9g9xnNEYKOsQLg46mwbOj8MRI8eg2nVmSLta/LZFPmjwJT9zi8RET1zE0z8wzzUwoVhNEBVxowWfJU7vw+uKGrMM9yQKqG271UOTPl2f/RjmEoviGWnn5gL/+Eyp2Upz6xFKtQNssovFsLT1s8a2TLeq9lLGjcCS19ayRNIOiFnxrjIUU6W2ZqYPsyFXXkBzuvT6ftYSE=
Prime1: 8aaqX8myNZ0oi3sz9pXXzCyt3K19V36gWkBlzB4en6LXogoDPTRSMhGsEHaIczTNCtLhd6NCed4DYf30E9MQYGil4c2QAGgjgZK1+8dxyVZCmjY5XsMoBh/Hj8YGsKCSvR3Hk1LYEML1NZCB7qxfHfOwkLAo8S8h68q5J36FgHHfHAWNlKFOdtFEw4wcGm5UjFDGJtsyhziN+973EHN6HNwdUTLWlA1Ds0KPGTD8xecbFBcdGBSg15uffKr9sKl/CsXfgHp+bxcuH5xKGbspfTQwUkkqQbNjlL7yRkyCddBRWcIFjYPsnJyh8W242mV8w367mUBN59V+b8lQviJfHw==
Prime2: 4V0kdtVQtfsmhReBA8K6E7xkdx0UvAok5d5VqNwd0HPEcBbo3/XmbwL93DrqKPpsZ0uppERK3dg1WvJ8AFzKSGuWkffZdMITdN/earm7rQnPjrwWtMnuop9wkj3npWvOcMWhBbmUBD03U4Bq0bgoXVy2Bzag8u5SFfPC4F9xBm1JCF8fB3K+PnV9fqx5dCMBdxVHe9aPkqpp/eul3lkHbTjrVWyG/goS+Dpuw9jIOygeDlfibfm8fHwKUcGB3fqp/tu07FXirgyBB5OvP3MeRDWgqfxfgo55lxiNl9GSFPVluNJ/p5vU2simbRKw6AkRLQUYE6iSAG/Kq2nxt8R8CQ==
Exponent1: y5V7Ihn93ndZyjDwtUTGOohFrY4n9AeFNqPcX1vctubtPeGrmuuyd+Y1jOUfzddlC0Jgm3dasOse9HaMJAuEV4SyhAq3z+/sQeSFFuqPbW0TzXHzYWePF6G8cd8GkdWl6lflZLO9vllRVmA5ZwenVseQMEWJKLBppony9Vf9RxooOiZfgiFnxmhFw20N3CKpblE6r0+qQQufatwMT7rJ3PiAZoErEC4gpCxl/HYt7tjmEkXqx/fRDfRZKCGyexxBIKVVx5rrW9IulIkKUKVCre3C7AAh7pogQhegayNYIcNwVetE3FWRiNvY/1pOCwjHVLg3ekQXnkJaM/lp4dV5Rw==
Exponent2: I/Aph3W++DZDz0ePQF1GNS1+y+vsSYxIlAufl1z6uCot8j4FBun8xEky2HLgsoY00Ugkllh5o+T9pTI0Cg7CB0h463Ad0lu8pI+qtVRHFHITEkz2RgBJuM86MWgDz8JgWmV5pyMP8pkcgIli/2yhqznEoWPZyMOufWew9PzjVkYJNneMyDBJHEa6K4AvohCPBEF1c88keBwK6P4yJkIGSCmiha3X3R0YJ1OSJFMmoyBjop/rMOR5ZVSWhLEaF58IiubYdDPCAUVnMiEf+jtOYUw4AcOIK5ay1yCIO+Skqgj0HsQarUzRZc5Hk+8+HNKNVaORUlk4Zy9sn2c2r7p6mQ==
Coefficient: 7TJvmOaFyYu3jqlORDmwPEXs/6aioNhq4ynuVZNEFqQxUDI9EuHjLtvsg0UFgYbVUwE7IZUXdbdCF7XWnBa6tQHqZFYtV9l4GyKvMvKhFmWIavdNc5AWiClf55GvB09TtdKVifE/x6E4hu0pumMXmYBTjRvk4qTg+DpxQ9EZ4aO0whjSEMTQg9gW5e6u/ucC2+qmgnDNPhLVm6PBRUzdqA93lnkVWX5mXK13uSe+kFEZ/0lK17uZniw/QGnUUnTypysvqJSqcr7U8LS9A4VI6dLjniu1XuEDGX61dXMmH8eX+MNoYd/zAq5HenN4iX5G+TckuuiaOaDPel1q1Q0A7w==
Created: 20171212170749
Publish: 20171212170749
Activate: 20171212170749
`
	k := pubkey.(*dns.DNSKEY)

	privkey, _ := pubkey.(*dns.DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		"./123/keys/Ktructh.dev.+007+31758.private")

	rrRecordA := &dns.A{
		Hdr: dns.RR_Header{Name: "tructh.dev.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   net.ParseIP("10.0.1.123"),
	}



	sig := new(dns.RRSIG)
	sig.Hdr = dns.RR_Header{"tructh.dev", dns.TypeRRSIG, dns.ClassINET, 1, 0}
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	//sig.TypeCovered = dns.TypeA
	//sig.Labels = 2
	//sig.OrigTtl = uint32(resultRecordA.Ttl)
	sig.Algorithm = k.Algorithm
	sig.KeyTag = k.KeyTag()
	sig.SignerName = k.Hdr.Name

	if err := sig.Sign(privkey.(*rsa.PrivateKey), []dns.RR{rrRecordA}); err != nil {
		fmt.Println("Sign",err)
	}
	if err := sig.Verify(k, []dns.RR{rrRecordA}); err != nil {
		fmt.Println("Verify",err)
	}
	m.Answer = append(m.Answer,sig)
}

func GetDNSKEY(m *dns.Msg){
	pubkey1, _ := dns.ReadRR(strings.NewReader(`tructh.xyz. IN DNSKEY 256 3 8 AwEAAc/Bso4hkm58/KH1m66l5AkDyalWLvLOMq0cPxB7oGfoPz/nIzFe JbdGX7jEJhSdq1Xmjts2Tkl1F79Hw3foWW8XX7IW/5JsGasdAtltWz6S 9YpfuFEBRA8nDwblkD3tlHYiqAjfujMeBaWmR8Q0G3NF69xy6HAnvVxM mmMlYjL1`), "./keys/Ktructh.xyz.+008+20826.key")
	pubkey2, _ := dns.ReadRR(strings.NewReader(`tructh.xyz. IN DNSKEY 257 3 8 AwEAAb9WNQqyj6CSQJ7rppXHB2wwvtnmtdhWOw7qi8MOLvwZkpO0cihl D9ZcG3MurIxrSxa02A8T4r7ZT9Pzf8GTNQml/gAA8Ep3gHtC3InBzSzG REVJ0JM0DOggnAyqrSD294KlrB3HNNcPvdg4T0wesooLTmuTatzbdeXK 2uXdQM3F`), "./keys/Ktructh.xyz.+008+29704.key")
	pubkey1 = pubkey1.(*dns.DNSKEY)
	pubkey2 = pubkey2.(*dns.DNSKEY)
	m.Answer = append(m.Answer,pubkey1)
	m.Answer = append(m.Answer,pubkey2)
}

func GetDNSDS(m *dns.Msg){
	pubkey1, _ := dns.ReadRR(strings.NewReader(`tructh.xyz. IN DNSKEY 256 3 8 AwEAAc/Bso4hkm58/KH1m66l5AkDyalWLvLOMq0cPxB7oGfoPz/nIzFe JbdGX7jEJhSdq1Xmjts2Tkl1F79Hw3foWW8XX7IW/5JsGasdAtltWz6S 9YpfuFEBRA8nDwblkD3tlHYiqAjfujMeBaWmR8Q0G3NF69xy6HAnvVxM mmMlYjL1`), "./keys/Ktructh.xyz.+008+20826.key")
	pubkey2, _ := dns.ReadRR(strings.NewReader(`tructh.xyz. IN DNSKEY 257 3 8 AwEAAb9WNQqyj6CSQJ7rppXHB2wwvtnmtdhWOw7qi8MOLvwZkpO0cihl D9ZcG3MurIxrSxa02A8T4r7ZT9Pzf8GTNQml/gAA8Ep3gHtC3InBzSzG REVJ0JM0DOggnAyqrSD294KlrB3HNNcPvdg4T0wesooLTmuTatzbdeXK 2uXdQM3F`), "./keys/Ktructh.xyz.+008+29704.key")

	ds1 := pubkey1.(*dns.DNSKEY).ToDS(dns.SHA256)
	ds2 := pubkey2.(*dns.DNSKEY).ToDS(dns.SHA256)

	m.Answer = append(m.Answer,ds1)
	m.Answer = append(m.Answer,ds2)
}

func GetDNSSOA(m *dns.Msg){
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{"tructh.xyz.", dns.TypeSOA, dns.ClassINET, 14400, 0}
	soa.Ns = "ns1.tructh.xyz."
	soa.Mbox = "ns2.tructh.xyz."
	soa.Serial = 1513346597
	soa.Refresh = 7200
	soa.Retry = 1800
	soa.Expire = 604800
	soa.Minttl = 120
	m.Answer = append(m.Answer,soa)
}

func SaveLog(msg *dns.Msg){
	start := time.Now()
	str := `
		NAME: `+msg.Question[0].Name+`
		NAME: `+strconv.Itoa(int(msg.Question[0].Qclass))+`
		NAME: `+strconv.Itoa(int(msg.Question[0].Qtype))+`
	`
	ioutil.WriteFile("./logs/log_"+string(strconv.FormatInt(start.Unix(), 10)) + ".log", []byte(str), 0644)
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	SaveLog(r)
	domainName, suffixDomain, errorDomain := ValidDomain(r.Question[0].Name)
	if errorDomain != nil {
		return
	}
	var (
		v4  bool
		//rr  dns.RR
		//str string
		a   net.IP
	)
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		//str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		//str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	//if v4 {
	//	rr = &dns.A{
	//		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
	//		A:   a.To4(),
	//	}
	//} else {
	//	rr = &dns.AAAA{
	//		Hdr:  dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
	//		AAAA: a,
	//	}
	//}

	//t := &dns.TXT{
	//	Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
	//	Txt: []string{str},
	//}
	switch r.Question[0].Qtype {
	default:
		fallthrough
	case dns.TypeTXT:
		resultRecordTXT, errMain := QueryRecordTXT(domainName, suffixDomain)
		if errMain != nil {
			return
		}
		for _, val := range resultRecordTXT {
			xT := &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
				Txt: []string{val.Str},
			}
			m.Answer = append(m.Answer, xT)
		}

	case dns.TypeCNAME:
		resultRecordCNAME, errMain := QueryRecordCNAME(domainName, suffixDomain)
		if errMain != nil {
			soa := new(dns.SOA)
			soa.Hdr = dns.RR_Header{"tructh.xyz.", dns.TypeSOA, dns.ClassINET, 14400, 0}
			soa.Ns = "ns1.tructh.xyz."
			soa.Mbox = "ns2.tructh.xyz."
			soa.Serial = 1513346597
			soa.Refresh = 7200
			soa.Retry = 1800
			soa.Expire = 604800
			soa.Minttl = 120
			m.Ns = append(m.Ns,soa)
		}else{

			xCNAME := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0},
				Target: resultRecordCNAME.Str + ".",
			}
			m.Answer = append(m.Answer, xCNAME)
		}
	case dns.TypeAAAA, dns.TypeA:
		resultRecordA, errMain := QueryRecordA(domainName, suffixDomain)
		if errMain != nil {
			return
		}
		var rrRecordA dns.RR
		if v4 {
			rrRecordA = &dns.A{
				Hdr: dns.RR_Header{Name: resultRecordA.Name + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(resultRecordA.Ttl)},
				A:   net.ParseIP(resultRecordA.Ip),
			}
		} else {
			rrRecordA = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: resultRecordA.Name + ".", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
				AAAA: a,
			}
		}
		//getKeySign(m)

		//key := new(dns.DNSKEY)
		//key.Hdr.Name = rrRecordA.Header().Name
		//key.Hdr.Rrtype = dns.TypeDNSKEY
		//key.Hdr.Class = dns.ClassINET
		//key.Hdr.Ttl = 1
		//key.Flags = 256
		//key.Protocol = 3
		//key.Algorithm = dns.RSASHA256
		//key.PublicKey = "AwEAAbA7XnJNxhV6989stpVJvDtp4pfJhMuLuXhqsXjOIer8PH2RDs2mfeTHpg+TlKl+C9Jzyr+qxuw29frZm6C8J4LkGs79WU9kIiLIBBjHVBuKOalarG7h6ROGiuM8nd/T4tDSPrRW+JXf7wqziDWN3lORNRjtS+EpChhAybCR2bR/"
		//priv, _ := key.Generate(1024)
		//
		//fmt.Println(priv)
		////fmt.Println(key.ToCDNSKEY())
		//
		//sig := new(dns.RRSIG)
		//sig.Hdr = dns.RR_Header{rrRecordA.Header().Name, dns.TypeRRSIG, dns.ClassINET, 1, 0}
		//sig.TypeCovered = dns.TypeA
		//sig.Algorithm = dns.RSASHA256
		//sig.Labels = 2
		//sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
		//sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
		//sig.OrigTtl = uint32(resultRecordA.Ttl)
		////sig.KeyTag = key.KeyTag()
		//sig.KeyTag = 12174
		//sig.SignerName = rrRecordA.Header().Name
		//sig.Signature = "WsfzxwTP9mJ2siVLjRaqre+KoHwEOOGZozVaWEaBoF3oirANwUzQDtUzzzI3cYAziY9ejL6Qcg2c8irQADB1rx37dsFOfN9O8//ZTzr/7lYN8QpE+roOYtgpw9/IpAAwW402mlXpaaAxzDE3UDJCTD0iaIh0JZ3taSn9eY/dEDI="

		//if err := sig.Sign(priv.(*rsa.PrivateKey), []dns.RR{rrRecordA}); err != nil {
		//	fmt.Println(err)
		//}
		//if err := sig.Verify(key, []dns.RR{rrRecordA}); err != nil {
		//	fmt.Println(err)
		//}
		//fmt.Println(key.PublicKey)
		//fmt.Println(sig.Signature)
		//fmt.Println(key.KeyTag())

		//soa := new(dns.SOA)
		//soa.Hdr = dns.RR_Header{"miek.nl.", dns.TypeSOA, dns.ClassINET, 14400, 0}
		//soa.Ns = "open.nlnetlabs.nl."
		//soa.Mbox = "miekg.atoom.net."
		//soa.Serial = 1293945905
		//soa.Refresh = 14400
		//soa.Retry = 3600
		//soa.Expire = 604800
		//soa.Minttl = 86400
		//
		//sig := new(dns.RRSIG)
		//sig.Hdr = dns.RR_Header{"miek.nl.", dns.TypeRRSIG, dns.ClassINET, 14400, 0}
		//sig.TypeCovered = dns.TypeSOA
		//sig.Algorithm = dns.RSASHA256
		//sig.Labels = 2
		//sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
		//sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
		//sig.OrigTtl = 1
		//sig.KeyTag = 12051
		//sig.SignerName = "miek.nl."
		////sig.Signature = "oMCbslaAVIp/8kVtLSms3tDABpcPRUgHLrOR48OOplkYo+8TeEGWwkSwaz/MRo2fB4FxW0qj/hTlIjUGuACSd+b1wKdH5GvzRJc2pFmxtCbm55ygAh4EUL0F6U5cKtGJGSXxxg6UFCQ0doJCmiGFa78LolaUOXImJrk6AFrGa0M="
		//
		//key := new(dns.DNSKEY)
		//key.Hdr.Name = "miek.nl."
		//key.Hdr.Class = dns.ClassINET
		//key.Hdr.Ttl = 1
		//key.Flags = 256
		//key.Protocol = 3
		//key.Algorithm = dns.RSASHA256
		//
		//priv, _ := key.Generate(1024)
		//
		//fmt.Println(priv)
		//if err := sig.Sign(priv.(*rsa.PrivateKey), []dns.RR{soa}); err != nil {
		//	fmt.Println("Sign",err)
		//}
		//fmt.Println(key)
		//if err := sig.Verify(key, []dns.RR{soa}); err != nil {
		//	fmt.Println("Verify",err)
		//}

		//key.PublicKey = "AwEAAcNEU67LJI5GEgF9QLNqLO1SMq1EdoQ6E9f85ha0k0ewQGCblyW2836GiVsm6k8Kr5ECIoMJ6fZWf3CQSQ9ycWfTyOHfmI3eQ/1Covhb2y4bAmL/07PhrL7ozWBW3wBfM335Ft9xjtXHPy7ztCbV9qZ4TVDTW/Iyg0PiwgoXVesz"

		// It should validate. Period is checked separately, so this will keep on working
		//if sig.Verify(key, []dns.RR{soa}) != nil {
		//	fmt.Println("error")
		//}

		//		pubkey, _ := dns.ReadRR(strings.NewReader(`
		//tructh.dev. IN DNSKEY 257 3 7 AwEAAdS7Z7WxNcL/fGSU+34/PnV4WszCJbm+wIHmBslF4RQm6noOtaA8 cE1/aF23sakCHDtvMYsSh+z0Un/xU4+ahnhwIj9PtPm6wA4AFAS7/mG/ cu4HgENsYUPsukBsOjyfvs34OnKL+/NppymsBxRzG8I9uilovETQZLfN rR2sWc9P1Jj+ZWCjICQFnDLYtthGuKc913T8ttjJtxhuhWs9WMaAcMqS F6wq1Ox8QbJm6hPCESMnxEfZ59SDKAN0bZvLDCUasqNvsMIlaqCn66gK fB26WjQ9lFdIjBCiXZEJ8Nox2dSyQmbWnA/lzlIGOL7i4MZmEI0l37GC 8huTy9dTPGYDwfHISyYKxEfBcJjJDtw/HrFdr7uzpwfNl9TV7/v940FW WtQLQqOySjZVb2OtbWZB+zf8zM9gKtbgCU9F6elgBD5HgYFw0/50dZif Xwsvnb5BWC3lv7mxWdaEF3mg5q392IQVRHyZ3ZtcjGFAc8Yfr3Wz6tOw mR3x2+hTIl9uNi4ngT8vmCQERL3kKLRM916k+wXcBXdedWmIwzRWESTj ohxVyNR+sBr6JUKNvvWPEu+L0bVnlgY1prMH2l5zww7l/uuJan87UEyx 0v/Tw9Xt970TfgmTu2KoRON1JQNavRNR+H/KMowls3oYh/jd0oiCy3mb NDlHsohBl25SBFwX
		//`), "./keys/Ktructh.dev.+007+31758.key")
		//
		//		privStr := `Private-key-format: v1.3
		//Algorithm: 7 (NSEC3RSASHA1)
		//Modulus: 1LtntbE1wv98ZJT7fj8+dXhazMIlub7AgeYGyUXhFCbqeg61oDxwTX9oXbexqQIcO28xixKH7PRSf/FTj5qGeHAiP0+0+brADgAUBLv+Yb9y7geAQ2xhQ+y6QGw6PJ++zfg6cov782mnKawHFHMbwj26KWi8RNBkt82tHaxZz0/UmP5lYKMgJAWcMti22Ea4pz3XdPy22Mm3GG6Faz1YxoBwypIXrCrU7HxBsmbqE8IRIyfER9nn1IMoA3Rtm8sMJRqyo2+wwiVqoKfrqAp8HbpaND2UV0iMEKJdkQnw2jHZ1LJCZtacD+XOUgY4vuLgxmYQjSXfsYLyG5PL11M8ZgPB8chLJgrER8FwmMkO3D8esV2vu7OnB82X1NXv+/3jQVZa1AtCo7JKNlVvY61tZkH7N/zMz2Aq1uAJT0Xp6WAEPkeBgXDT/nR1mJ9fCy+dvkFYLeW/ubFZ1oQXeaDmrf3YhBVEfJndm1yMYUBzxh+vdbPq07CZHfHb6FMiX242LieBPy+YJAREveQotEz3XqT7BdwFd151aYjDNFYRJOOiHFXI1H6wGvolQo2+9Y8S74vRtWeWBjWmswfaXnPDDuX+64lqfztQTLHS/9PD1e33vRN+CZO7YqhE43UlA1q9E1H4f8oyjCWzehiH+N3SiILLeZs0OUeyiEGXblIEXBc=
		//PublicExponent: AQAB
		//PrivateExponent: SCHbgqI6Boq21SwnMqGjPhW3RCK4xAjIIcOrnWfScBDaBNUkBNc5hS2kZ9K3rQUIKacEd5GrAU+/AZ8EpHbTDdeH5UvTo7INGTIxl4FfOim+gLOObE49lNiaNun7vT61ZgW7W8fXgKvcgKbSJ774NJ7VluDqpbK71A8rmhoswbzh65anLWNirJQyaJNPPHqOdjbj7cka/ts2+FPRbZF5nqVCmY179Wb4l89yP1niGRz+zprXVT2v/EEUukcqO19YGOS6mexvVQV26E7H+0zC1RmxKHGQ8R+qTqGfdGSYhIPOxu5C0bgHZuSXVvzBFQi9Csjk59dlyD0MdwlgXvzcR2S3tAWaRrZ1JHhkZLBc407xUaH7UGf4mrx5yX81FOSx9X/y2o/DO9qz+44wiaM9H9jDjOMdGYzgbhacgmHMIt0+q//tkXxGD1zNDQtzP5FmNgp30AVMIjfypa2/zsVszArfo5g1MnS62K9g9xnNEYKOsQLg46mwbOj8MRI8eg2nVmSLta/LZFPmjwJT9zi8RET1zE0z8wzzUwoVhNEBVxowWfJU7vw+uKGrMM9yQKqG271UOTPl2f/RjmEoviGWnn5gL/+Eyp2Upz6xFKtQNssovFsLT1s8a2TLeq9lLGjcCS19ayRNIOiFnxrjIUU6W2ZqYPsyFXXkBzuvT6ftYSE=
		//Prime1: 8aaqX8myNZ0oi3sz9pXXzCyt3K19V36gWkBlzB4en6LXogoDPTRSMhGsEHaIczTNCtLhd6NCed4DYf30E9MQYGil4c2QAGgjgZK1+8dxyVZCmjY5XsMoBh/Hj8YGsKCSvR3Hk1LYEML1NZCB7qxfHfOwkLAo8S8h68q5J36FgHHfHAWNlKFOdtFEw4wcGm5UjFDGJtsyhziN+973EHN6HNwdUTLWlA1Ds0KPGTD8xecbFBcdGBSg15uffKr9sKl/CsXfgHp+bxcuH5xKGbspfTQwUkkqQbNjlL7yRkyCddBRWcIFjYPsnJyh8W242mV8w367mUBN59V+b8lQviJfHw==
		//Prime2: 4V0kdtVQtfsmhReBA8K6E7xkdx0UvAok5d5VqNwd0HPEcBbo3/XmbwL93DrqKPpsZ0uppERK3dg1WvJ8AFzKSGuWkffZdMITdN/earm7rQnPjrwWtMnuop9wkj3npWvOcMWhBbmUBD03U4Bq0bgoXVy2Bzag8u5SFfPC4F9xBm1JCF8fB3K+PnV9fqx5dCMBdxVHe9aPkqpp/eul3lkHbTjrVWyG/goS+Dpuw9jIOygeDlfibfm8fHwKUcGB3fqp/tu07FXirgyBB5OvP3MeRDWgqfxfgo55lxiNl9GSFPVluNJ/p5vU2simbRKw6AkRLQUYE6iSAG/Kq2nxt8R8CQ==
		//Exponent1: y5V7Ihn93ndZyjDwtUTGOohFrY4n9AeFNqPcX1vctubtPeGrmuuyd+Y1jOUfzddlC0Jgm3dasOse9HaMJAuEV4SyhAq3z+/sQeSFFuqPbW0TzXHzYWePF6G8cd8GkdWl6lflZLO9vllRVmA5ZwenVseQMEWJKLBppony9Vf9RxooOiZfgiFnxmhFw20N3CKpblE6r0+qQQufatwMT7rJ3PiAZoErEC4gpCxl/HYt7tjmEkXqx/fRDfRZKCGyexxBIKVVx5rrW9IulIkKUKVCre3C7AAh7pogQhegayNYIcNwVetE3FWRiNvY/1pOCwjHVLg3ekQXnkJaM/lp4dV5Rw==
		//Exponent2: I/Aph3W++DZDz0ePQF1GNS1+y+vsSYxIlAufl1z6uCot8j4FBun8xEky2HLgsoY00Ugkllh5o+T9pTI0Cg7CB0h463Ad0lu8pI+qtVRHFHITEkz2RgBJuM86MWgDz8JgWmV5pyMP8pkcgIli/2yhqznEoWPZyMOufWew9PzjVkYJNneMyDBJHEa6K4AvohCPBEF1c88keBwK6P4yJkIGSCmiha3X3R0YJ1OSJFMmoyBjop/rMOR5ZVSWhLEaF58IiubYdDPCAUVnMiEf+jtOYUw4AcOIK5ay1yCIO+Skqgj0HsQarUzRZc5Hk+8+HNKNVaORUlk4Zy9sn2c2r7p6mQ==
		//Coefficient: 7TJvmOaFyYu3jqlORDmwPEXs/6aioNhq4ynuVZNEFqQxUDI9EuHjLtvsg0UFgYbVUwE7IZUXdbdCF7XWnBa6tQHqZFYtV9l4GyKvMvKhFmWIavdNc5AWiClf55GvB09TtdKVifE/x6E4hu0pumMXmYBTjRvk4qTg+DpxQ9EZ4aO0whjSEMTQg9gW5e6u/ucC2+qmgnDNPhLVm6PBRUzdqA93lnkVWX5mXK13uSe+kFEZ/0lK17uZniw/QGnUUnTypysvqJSqcr7U8LS9A4VI6dLjniu1XuEDGX61dXMmH8eX+MNoYd/zAq5HenN4iX5G+TckuuiaOaDPel1q1Q0A7w==
		//Created: 20171212170749
		//Publish: 20171212170749
		//Activate: 20171212170749
		//`
		//
		//		privkey, _ := pubkey.(*dns.DNSKEY).ReadPrivateKey(strings.NewReader(privStr),
		//			"./keys/Ktructh.dev.+007+31758.private")
		//		fmt.Println(privkey)
		//
		//		abc,_ := pubkey.(*dns.DNSKEY).NewPrivateKey(privStr)
		//
		//		k := pubkey.(*dns.DNSKEY)
		//
		//		sig := new(dns.RRSIG)
		//		sig.Hdr = dns.RR_Header{rrRecordA.Header().Name, dns.TypeRRSIG, dns.ClassINET, 1, 0}
		//		sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
		//		sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
		//		//sig.TypeCovered = dns.TypeA
		//		//sig.Labels = 2
		//		//sig.OrigTtl = uint32(resultRecordA.Ttl)
		//		sig.Algorithm = k.Algorithm
		//		sig.KeyTag = k.KeyTag()
		//		sig.SignerName = k.Hdr.Name
		//
		//
		//		if err := sig.Sign(abc.(*rsa.PrivateKey), []dns.RR{rrRecordA}); err != nil {
		//			fmt.Println("Sign",err)
		//		}
		//		//fmt.Println(key)
		//		//if err := sig.Verify(key, []dns.RR{soa}); err != nil {
		//		//	fmt.Println("Verify",err)
		//		//}
		//
		//		fmt.Println(privkey)
		//		fmt.Println(pubkey.(*dns.DNSKEY).ToDS(dns.SHA1))
		//		getKeySign()
		m.Answer = append(m.Answer, rrRecordA)
		soa := new(dns.SOA)
		soa.Hdr = dns.RR_Header{"tructh.xyz.", dns.TypeSOA, dns.ClassINET, 14400, 0}
		soa.Ns = "ns1.tructh.xyz."
		soa.Mbox = "ns2.tructh.xyz."
		soa.Serial = 1513346597
		soa.Refresh = 7200
		soa.Retry = 1800
		soa.Expire = 604800
		soa.Minttl = 120
		m.Ns = append(m.Ns,soa)
		//		m.Answer = append(m.Answer, pubkey)
		//nn := []byte(m.String())

		//m.Answer = append(m.Answer,key)
		//m.Extra = append(m.Extra, t)
	case dns.TypeMX:
		resultRecordMX, errMain := QueryRecordCMX(domainName, suffixDomain)
		if errMain != nil {
			return
		}
		for _, val := range resultRecordMX {
			xMX := new(dns.MX)
			xMX.Hdr = dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    3600,
			}
			xMX.Preference = uint16(val.Get("priority").Int())
			xMX.Mx = val.Get("server").Str + "."
			m.Answer = append(m.Answer, xMX)
		}
	case dns.TypeNS:
		ns1 := &dns.NS{
			Hdr:    dns.RR_Header{Name: "tructh.xyz.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 21599},
			Ns: "ns1.tructh.xyz.",
		}
		ns2 := &dns.NS{
			Hdr:    dns.RR_Header{Name: "tructh.xyz.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 21599},
			Ns: "ns2.tructh.xyz.",
		}
		m.Answer = append(m.Answer,ns1)
		m.Answer = append(m.Answer,ns2)
	case dns.TypeSOA:
		GetDNSSOA(m)
	case dns.TypeDNSKEY:
		GetDNSKEY(m)
	case dns.TypeDS:
		GetDNSDS(m)

	//case dns.TypeAXFR, dns.TypeIXFR:
	//	c := make(chan *dns.Envelope)
	//	tr := new(dns.Transfer)
	//	defer close(c)
	//	if err := tr.Out(w, r, c); err != nil {
	//		return
	//	}
	//	soa, _ := dns.NewRR(`whoami.miek.nl. 0 IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
	//	c <- &dns.Envelope{RR: []dns.RR{soa, t, rr, soa}}
	//	w.Hijack()
	//	// w.Close() // Client closes connection
	//	return
	}



	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	// set TC when question is tc.miek.nl.
	//if m.Question[0].Name == "tc.miek.nl." {
	//	m.Truncated = true
	//	// send half a message
	//	buf, _ := m.Pack()
	//	w.Write(buf[:len(buf)/2])
	//	return
	//}
	fmt.Println(m)
	w.WriteMsg(m)
}

func serve(net, name, secret string) {
	switch name {
	case "":
		server := &dns.Server{Addr: ":53", Net: net, TsigSecret: nil}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":53", Net: net, TsigSecret: map[string]string{name: secret}}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	fmt.Println(*tsig)
	if *tsig != "" {
		fmt.Println("yyy")
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// dns.HandleFunc("miek.nl.", handleReflect)
	dns.HandleFunc(".", handleReflect)
	go serve("tcp", name, secret)
	go serve("udp", name, secret)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
