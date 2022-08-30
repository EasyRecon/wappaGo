package analyze

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze)analyze_scriptSrc_main(technoName string,key string){
	for _, scriptCrc := range a.SrcList {
		if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
			a.analyze_scriptSrc(technoName,a.ResultGlobal[technoName].(map[string]interface{})[key].(string),scriptCrc)
		} else {
			for _, scriptSrcArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
				finalRegex := strings.ReplaceAll(scriptSrcArray.(string), "/", "\\/")		
				a.analyze_scriptSrc(technoName,finalRegex,scriptCrc)
			}
		}
	}
}

func  (a *Analyze) analyze_scriptSrc(technoName string,regexStr string,scriptCrc string){
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	findRegex, _ := regexp.MatchString("(?i)"+regex[0], scriptCrc)
	if findRegex {
		technoTemp := a.NewTechno(technoName)
		compiledregex := regexp.MustCompile("(?i)" + regex[0])
		regexGroup := compiledregex.FindAllStringSubmatch(scriptCrc, -1)

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