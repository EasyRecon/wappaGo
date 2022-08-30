package analyze


import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)



func (a *Analyze)analyze_dom_main(technoName string,key string, doc *goquery.Document){
	if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
		doc.Find(a.ResultGlobal[technoName].(map[string]interface{})[key].(string)).Each(func(i int, s *goquery.Selection) {
			technoTemp := a.NewTechno(technoName)
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		})
	} else if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "map[string]interface {}" {
		for domKey, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
			for domKeyElement, domElement := range domArray.(map[string]interface{}) {
				if fmt.Sprintf("%T", domElement) == "string" {
					doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
						a.analyze_dom_valued(technoName,domElement)
					})
				} else if fmt.Sprintf("%T", domElement) == "map[string]interface {}" {
					for domKeyElement2, domElement2 := range domElement.(map[string]interface{}) {
						if domKeyElement == "attributes" {
							doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
								a.analyze_dom_attribute(technoName,domKeyElement2,domElement2,s)
							})
						} else {
							a.analyze_dom_exist(technoName,domKeyElement2,domKey)
						}
					}
				}
			}
		}
	} else {
		for _, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
			doc.Find(domArray.(string)).Each(func(i int, s *goquery.Selection) {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			})
		}
	}			
}
func  (a *Analyze) analyze_dom_exist(technoName string,domKeyElement2 string,domKey string ){
	var res interface{}
	chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(a.Ctx)
	//fmt.Println(res, "(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()")
	if res == true {
		technoTemp := a.NewTechno(technoName)												
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}


func  (a *Analyze) analyze_dom_attribute(technoName string,domKeyElement2 string,domElement2 interface{},s *goquery.Selection){
	dommAttr, _ := s.Attr(domKeyElement2)
	if dommAttr != "" {
		if domKeyElement2 != "" {
			regex := strings.Split(domElement2.(string), "\\;")
			findRegex, _ := regexp.MatchString("(?i)"+regex[0], dommAttr)
			if findRegex {
				technoTemp := a.NewTechno(technoName)
				compiledregex := regexp.MustCompile("(?i)" + regex[0])
				regexGroup := compiledregex.FindAllStringSubmatch(dommAttr, -1)
																
				if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
					versionGrp := strings.Split(regex[1], "\\")
																		
					if len(versionGrp) > 1 {
						offset, _ := strconv.Atoi(versionGrp[1])
																			//fmt.Println(versionGrp)
						technoTemp.Version = regexGroup[0][offset]
					}
				}
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		} else {
			technoTemp := a.NewTechno(technoName)
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		}
	}
}


func  (a *Analyze) analyze_dom_valued(technoName string,domElement interface{}){
	if domElement == "" {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	} else {
		regex := strings.Split(domElement.(string), "\\;")

		findregex, _ := regexp.MatchString("(?i)"+regex[0], a.Body)
		if findregex {
			//fmt.Println(technoName)
			technoTemp := a.NewTechno(technoName)
			compiledregex := regexp.MustCompile("(?i)" + regex[0])
			regexGroup := compiledregex.FindAllStringSubmatch(a.Body, -1)

			if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
				versionGrp := strings.Split(regex[1], "\\")

				if len(versionGrp) > 1 {
					offset, _ := strconv.Atoi(versionGrp[1])
					//fmt.Println(regexGroup[0][offset])
					technoTemp.Version = regexGroup[0][offset]
				}
			}
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		}
	}
}
