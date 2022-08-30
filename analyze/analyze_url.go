package analyze

import (
	"fmt"
	"regexp"
	"github.com/EasyRecon/wappaGo/technologies"
)


func (a *Analyze)analyze_url_main(technoName string,key string){
	if a.Hote.Location != "" {
		if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
			a.analyze_url(technoName,a.ResultGlobal[technoName].(map[string]interface{})[key].(string))
		} else {
			for _, url := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
				a.analyze_url(technoName,url.(string))
			}
		}
	}
}

func  (a *Analyze) analyze_url(technoName string,regexStr string){
	findregex, _ := regexp.MatchString("(?i)"+regexStr, a.Hote.Location)
	if findregex == true {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}
