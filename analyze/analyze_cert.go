package analyze

import (
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze)analyze_cert_main(technoName string,key string){
	if a.CertIssuer == a.ResultGlobal[technoName].(map[string]interface{})[key].(string) {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}