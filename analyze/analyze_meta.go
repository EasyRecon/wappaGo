package analyze

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"

)


func (a *Analyze)analyze_meta_main(technoName string,key string,doc *goquery.Document){
	for metaKey, metaProperties := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		doc.Find("meta[name=\"" + metaKey + "\" i]").Each(func(i int, s *goquery.Selection) {
			if fmt.Sprintf("%T", metaProperties) == "string" {
				a.analyze_meta(s,metaProperties,technoName)
			} else {
				for _, metaPropertiess := range metaProperties.([]interface{}) {
					a.analyze_meta(s,metaPropertiess,technoName)
				}
			}
		})
	}
}


func  (a *Analyze) analyze_meta(s *goquery.Selection,metaProperties interface{},technoName string){
	metaValue, _ := s.Attr("content")
	regex := strings.Split(fmt.Sprintf("%v", metaProperties), "\\;")
	findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
	if findregex == true {
		//fmt.Println(technoName)
		technoTemp := a.NewTechno(technoName)
		compiledregex := regexp.MustCompile("(?i)" + regex[0])
		regexGroup := compiledregex.FindAllStringSubmatch(metaValue, -1)

		if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
			versionGrp := strings.Split(regex[1], "\\")
			if len(versionGrp) > 1 {
				offset, _ := strconv.Atoi(versionGrp[1])
				technoTemp.Version = regexGroup[0][offset]
			}
		}
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}