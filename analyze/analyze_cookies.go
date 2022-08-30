package analyze

import (
	"github.com/EasyRecon/wappaGo/technologies"
)

func  (a *Analyze) analyze_cookies_main(technoName string,key string){
	for cookieTechno, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		for _, cookie := range a.CookiesList {
			if cookieTechno == cookie.Name {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		}
	}
}