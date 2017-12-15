package queryDNS

import (
	"io/ioutil"
	"time"
	"errors"
	"math/rand"
	"github.com/tidwall/gjson"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"strings"
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
	}
	result := gjson.Get(ConfigDomain[domain],"records.A." + aliasM )

	if result.Exists(){
		listIps := result.Get("ips")
		var _t TypeRecordA
		var err error
		var realIp gjson.Result
		if listIps.Exists(){
			realIp, err = RandomWeightedSelect(listIps.Array(),int(result.Get("total").Int()))
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