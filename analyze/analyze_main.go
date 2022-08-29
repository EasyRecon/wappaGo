package analyze

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"github.com/EasyRecon/wappaGo/lib"
	structure "github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	cdp "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

)

type Analyze struct {
	ResultGlobal 	map[string]interface{}
	Resp 			structure.Response
	SrcList 		[]string
	Ctx 			context.Context
	Hote 			structure.Host
	CookiesList 	[]*network.Cookie
	Node 			*cdp.Node
	Body 			string
	Technos    		[]structure.Technologie
}


func (a *Analyze) Run() []structure.Technologie {
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(a.Body))
	//a.Hote := Host{}
	for technoName, _ := range a.ResultGlobal {
		for key, _ := range a.ResultGlobal[technoName].(map[string]interface{}) {
			if lib.Contains(structure.InterrestingKey, key) {
				if key == "js" {
					for js, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						if a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js] != "" { // just check if existe & match regex

							regex := strings.Split(fmt.Sprintf("%v", a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js]), "\\;")
							var res interface{}
							if regex[0] != "" {
								chromedp.Evaluate("(()=>{return "+js+".match(/"+regex[0]+"/gm)[0]})()", &res).Do(a.Ctx)
							} else {
								chromedp.Evaluate("(()=>{return (typeof "+js+" !== 'undefined' ? true : false})()", &res).Do(a.Ctx)
							}
							//fmt.Println(res,technoName,regex)
							if res != nil && res != false {
								
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if (len(regex) > 1 && strings.HasPrefix(regex[1], "confidence")) || (len(regex) > 2 && strings.HasPrefix(regex[2], "confidence")) {
									if len(regex) > 1 && strings.HasPrefix(regex[1], "confidence") {
										technoTemp.Confidence = strings.Split(regex[1], ":")[1]
									}
									if len(regex) > 2 && strings.HasPrefix(regex[2], "confidence") {
										technoTemp.Confidence = strings.Split(regex[1], ":")[1]
									}
								}
								if (len(regex) > 1 && strings.HasPrefix(regex[1], "version")) || (len(regex) > 2 && strings.HasPrefix(regex[2], "version")) {
									//fmt.Println(res,technoName,regex)
									if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
										technoTemp.Version = fmt.Sprintf("%v", res)
									}
									if len(regex) > 2 && strings.HasPrefix(regex[2], "version") {
										technoTemp.Version = fmt.Sprintf("%v", res)
									}
								}
								if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								a.Technos = append(a.Technos, technoTemp)
								a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
							}

						} else { // just check if existe
							var res interface{}
							chromedp.Evaluate("(()=>{ return (typeof "+js+" !== 'undefined' ? true : false)})()", &res).Do(a.Ctx)
							if res == true {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								a.Technos = append(a.Technos, technoTemp)
								a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)

							}

						}
					}

				}
				if key == "headers" {
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
										technoTemp := structure.Technologie{}

										technoTemp.Name = technoName
										if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
											technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
										}
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
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									a.Technos = append(a.Technos, technoTemp)
									a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
								}
							}
						}

					}
				}
				if key == "dom" {

					if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
						doc.Find(a.ResultGlobal[technoName].(map[string]interface{})[key].(string)).Each(func(i int, s *goquery.Selection) {
							technoTemp := structure.Technologie{}
							technoTemp.Name = technoName
							if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
								technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
							}
							a.Technos = append(a.Technos, technoTemp)
							a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
						})

					} else if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "map[string]interface {}" {

						for domKey, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {

							for domKeyElement, domElement := range domArray.(map[string]interface{}) {
								if fmt.Sprintf("%T", domElement) == "string" {
									doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
										if domElement == "" {
											technoTemp := structure.Technologie{}
											technoTemp.Name = technoName
											if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
												technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
											}
											a.Technos = append(a.Technos, technoTemp)
											a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
										} else {
											regex := strings.Split(domElement.(string), "\\;")

											findregex, _ := regexp.MatchString("(?i)"+regex[0], a.Body)
											if findregex {
												//fmt.Println(technoName)
												technoTemp := structure.Technologie{}
												technoTemp.Name = technoName
												if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
													technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
												}
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
									})

								} else if fmt.Sprintf("%T", domElement) == "map[string]interface {}" {
									for domKeyElement2, domElement2 := range domElement.(map[string]interface{}) {
									
										if domKeyElement == "attributes" {

											doc.Find(domKey).Each(func(i int, s *goquery.Selection) {

												dommAttr, _ := s.Attr(domKeyElement2)
												//	fmt.Println(dommAttr, "------")
												if dommAttr != "" {
													if domKeyElement2 != "" {
														regex := strings.Split(domElement2.(string), "\\;")
														findRegex, _ := regexp.MatchString("(?i)"+regex[0], dommAttr)


														if findRegex {
															technoTemp := structure.Technologie{}
															technoTemp.Name = technoName
															if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
																technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
															}

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
														technoTemp := structure.Technologie{}
														technoTemp.Name = technoName
														if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
															technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
														}
														a.Technos = append(a.Technos, technoTemp)
														a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
													}
												}

											})
										} else {
											var res interface{}
											chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(a.Ctx)
											//fmt.Println(res, "(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()")
											if res == true {
												technoTemp := structure.Technologie{}
												technoTemp.Name = technoName
												if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
													technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
												}
												a.Technos = append(a.Technos, technoTemp)
												a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
											}
										}
									}
								}
							}
						}

					} else {
						for _, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							doc.Find(domArray.(string)).Each(func(i int, s *goquery.Selection) {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								a.Technos = append(a.Technos, technoTemp)
								a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
							})
						}
					}
				}
				if key == "cookies" && len(a.CookiesList) > 0 {
					for cookieTechno, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						for _, cookie := range a.CookiesList {
							a.analyze_cookies(technoName,cookie,cookieTechno)
						}
					}
				}
				if key == "scriptSrc" {
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
				if key == "url" {
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
				if key == "html" || key == "text" {
					if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
						a.analyze_html(technoName, a.ResultGlobal[technoName].(map[string]interface{})[key])
						
					} else {
						for _, htmlRegex := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							a.analyze_html(technoName,htmlRegex)
						}
					}
				}
				if key == "meta" {
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
			}
		}
	}
	return a.Technos
}

func  (a *Analyze) analyze_dom(technoName string){

}
func  (a *Analyze) analyze_cookies(technoName string,cookie *network.Cookie,cookieTechno string){
	if cookieTechno == cookie.Name {
		technoTemp := structure.Technologie{}
		technoTemp.Name = technoName
		if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
			technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
		}
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}
func  (a *Analyze) analyze_scriptSrc(technoName string,regexStr string,scriptCrc string){
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	findRegex, _ := regexp.MatchString("(?i)"+regex[0], scriptCrc)
	if findRegex {
		technoTemp := structure.Technologie{}
		technoTemp.Name = technoName
		if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
			technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
		}
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


func  (a *Analyze) analyze_url(technoName string,regexStr string){
	findregex, _ := regexp.MatchString("(?i)"+regexStr, a.Hote.Location)
	if findregex == true {
		technoTemp := structure.Technologie{}
		technoTemp.Name = technoName
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}

func (a *Analyze) analyze_html(technoName string,regexStr interface{}) {
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	findregex, _ := regexp.MatchString("(?i)"+regex[0], a.Body)
	if findregex == true {
		technoTemp := structure.Technologie{}
		technoTemp.Name = technoName
		if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
			technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
		}
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

func  (a *Analyze) analyze_meta(s *goquery.Selection,metaProperties interface{},technoName string){
	metaValue, _ := s.Attr("content")
	regex := strings.Split(fmt.Sprintf("%v", metaProperties), "\\;")
	findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
	if findregex == true {
		//fmt.Println(technoName)
		technoTemp := structure.Technologie{}
		technoTemp.Name = technoName
		if a.ResultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
			technoTemp.Cpe = a.ResultGlobal[technoName].(map[string]interface{})["cpe"].(string)
		}
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