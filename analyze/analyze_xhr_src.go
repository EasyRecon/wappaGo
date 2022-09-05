package analyze

import(
	"fmt"
	"regexp"
	"github.com/EasyRecon/wappaGo/technologies"
)


func (a *Analyze)analyze_xhr_main(technoName string,key string){
	for _,url:=range a.XHRUrl {
		if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
			findRegex, _ := regexp.MatchString("(?i)"+a.ResultGlobal[technoName].(map[string]interface{})[key].(string), url)
			if findRegex {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		} else {
			for _, XHRArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
				findRegex, _ := regexp.MatchString("(?i)"+XHRArray.(string), url)
				if findRegex {
					technoTemp := a.NewTechno(technoName)
					a.Technos = append(a.Technos, technoTemp)
					a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
				}
			}
		}
	}
}