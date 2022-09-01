package analyze


import(

	"fmt"
)
func (a *Analyze) analyze_dns(technoName string,key string){
	for key,value := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{})   {
		fmt.Println(key,value)
	}
}