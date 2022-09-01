package analyze


import(

	"fmt"
	"github.com/EasyRecon/wappaGo/technologies"
	"regexp"
)
func (a *Analyze) analyze_dns_main(technoName string,key string){
	for key,value := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})    {
		var resultDNS []string
		switch key {
			case "TXT":
			    resultDNS = a.DnsData.TXT
		 	case "SOA":
			    resultDNS = a.DnsData.SOA
			case "NS":
			    resultDNS = a.DnsData.NS
			case "CNAME":
			    resultDNS = a.DnsData.CNAME
			case "MX":
			    resultDNS = a.DnsData.MX
		}
		if fmt.Sprintf("%T",value) == "string" {
			found := a.analyze_dns_regex(value.(string),resultDNS)
			if found {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		} else {
			for _,regex:= range value.([]interface{})  {
				found := a.analyze_dns_regex(regex.(string),resultDNS)
				if found {
					technoTemp := a.NewTechno(technoName)
					a.Technos = append(a.Technos, technoTemp)
					a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
				}
			}
		}
	}	
}

func (a *Analyze) analyze_dns_regex(regex string,resultsDNS []string)(bool){

	for _,resultDNS:= range resultsDNS {
		findregex, _ := regexp.MatchString("(?i)"+regex, resultDNS)
		if findregex {
			return true
		}
	}
	return false
}