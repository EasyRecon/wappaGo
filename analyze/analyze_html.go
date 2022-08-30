package analyze

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze)analyze_html_main(technoName string,key string){
	if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
		a.analyze_html(technoName, a.ResultGlobal[technoName].(map[string]interface{})[key])
	} else {
		for _, htmlRegex := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
			a.analyze_html(technoName,htmlRegex)
		}
	}
}

func (a *Analyze) analyze_html(technoName string,regexStr interface{}) {
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	findregex, _ := regexp.MatchString("(?i)"+regex[0], a.Body)
	if findregex == true {
		technoTemp := a.NewTechno(technoName)
		compiledregex := regexp.MustCompile("(?i)" + regex[0])
		regexGroup := compiledregex.FindAllStringSubmatch(a.Body, -1)

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