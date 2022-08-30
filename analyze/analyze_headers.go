package analyze

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)


func (a *Analyze)analyze_headers_main(technoName string,key string){
	for header, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		for headerName, _ := range a.Resp.Headers {
			if strings.ToLower(header) == strings.ToLower(headerName) {
				//headerValue := a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[header]
				if a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName] != "" {
					regex := strings.Split(fmt.Sprintf("%v", a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName]), "\\;")
					findregex, _ := regexp.MatchString("(?i)"+regex[0], a.Resp.Headers[headerName][0])
					//fmt.Println(findregex, technoName, headerName, a.Resp.Header[headerName][0])
					if findregex == true {
						//fmt.Println(technoName)
						technoTemp := a.NewTechno(technoName)
						compiledregex := regexp.MustCompile("(?i)" + regex[0])
						regexGroup := compiledregex.FindAllStringSubmatch(a.Resp.Headers[headerName][0], -1)

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
				} else {
					technoTemp := a.NewTechno(technoName)
						a.Technos = append(a.Technos, technoTemp)
						a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
				}
			}
		}
	}
}
