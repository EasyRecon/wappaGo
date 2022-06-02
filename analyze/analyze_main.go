package analyze

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func Run(resultGlobal map[string]interface{}, resp structure.Response, srcList []string, ctx context.Context, hote structure.Host, cookiesList []*network.Cookie, node *cdp.Node, body string) []structure.Technologie {

	var technos []structure.Technologie
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(body))
	//hote := Host{}
	for technoName, _ := range resultGlobal {
		for key, _ := range resultGlobal[technoName].(map[string]interface{}) {
			if lib.Contains(structure.InterrestingKey, key) {
				if key == "js" {
					for js, _ := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						if resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js] != "" { // just check if existe & match regex

							regex := strings.Split(fmt.Sprintf("%v", resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js]), "\\;")
							var res interface{}
							if regex[0] != "" {
								chromedp.Evaluate("return "+js+".match(/"+regex[0]+"/gm)[0]", &res).Do(ctx)
							} else {
								chromedp.Evaluate("return (typeof "+js+" !== 'undefined' ? true : false)", &res).Do(ctx)

							}
							if res != nil && res != false {
								//fmt.Println(js, regex)
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
									if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
										technoTemp.Version = fmt.Sprintf("%v", res)
									}
									if len(regex) > 2 && strings.HasPrefix(regex[2], "version") {
										technoTemp.Version = fmt.Sprintf("%v", res)
									}
								}
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
							}

						} else { // just check if existe
							var res interface{}
							chromedp.Evaluate("return (typeof "+js+" !== 'undefined' ? true : false)", &res).Do(ctx)
							if res == true {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)

							}

						}
					}

				}
				if key == "headers" {
					for header, _ := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						//fmt.Println(header, "---------------------", resp.Header)
						for headerName, _ := range resp.Headers {
							if strings.ToLower(header) == strings.ToLower(headerName) {
								//headerValue := resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[header]
								if resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName] != "" {
									regex := strings.Split(fmt.Sprintf("%v", resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName]), "\\;")

									findregex, _ := regexp.MatchString("(?i)"+regex[0], resp.Headers[headerName][0])
									//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
									if findregex == true {
										//fmt.Println(technoName)
										technoTemp := structure.Technologie{}

										technoTemp.Name = technoName
										if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
											technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
										}
										compiledregex := regexp.MustCompile("(?i)" + regex[0])
										regexGroup := compiledregex.FindAllStringSubmatch(resp.Headers[headerName][0], -1)

										if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
											versionGrp := strings.Split(regex[1], "\\")
											if len(versionGrp) > 1 {
												offset, _ := strconv.Atoi(versionGrp[1])
												//fmt.Println(regexGroup[0][offset])
												technoTemp.Version = regexGroup[0][offset]
											}
										}
										technos = append(technos, technoTemp)
										technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
									}
								} else {
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technos = append(technos, technoTemp)
									technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
								}
							}
						}

					}
				}
				if key == "dom" {

					if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {
						doc.Find(resultGlobal[technoName].(map[string]interface{})[key].(string)).Each(func(i int, s *goquery.Selection) {
							technoTemp := structure.Technologie{}
							technoTemp.Name = technoName
							if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
								technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
							}
							technos = append(technos, technoTemp)
							technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
						})

					} else if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "map[string]interface {}" {

						for domKey, domArray := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {

							for domKeyElement, domElement := range domArray.(map[string]interface{}) {
								if fmt.Sprintf("%T", domElement) == "string" {
									doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
										if domElement == "" {
											technoTemp := structure.Technologie{}
											technoTemp.Name = technoName
											if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
												technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
											}
											technos = append(technos, technoTemp)
											technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
										} else {
											regex := strings.Split(domElement.(string), "\\;")

											findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
											if findregex {
												//fmt.Println(technoName)
												technoTemp := structure.Technologie{}
												technoTemp.Name = technoName
												if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
													technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
												}
												compiledregex := regexp.MustCompile("(?i)" + regex[0])
												regexGroup := compiledregex.FindAllStringSubmatch(body, -1)

												if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
													versionGrp := strings.Split(regex[1], "\\")

													if len(versionGrp) > 1 {
														offset, _ := strconv.Atoi(versionGrp[1])
														//fmt.Println(regexGroup[0][offset])
														technoTemp.Version = regexGroup[0][offset]
													}
												}
												technos = append(technos, technoTemp)
												technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
											}
										}
									})

								} else if fmt.Sprintf("%T", domElement) == "map[string]interface {}" {
									for domKeyElement2, domElement2 := range domElement.(map[string]interface{}) {
										//fmt.Println(domKey, domKeyElement, domKeyElement2, domElement2, "------")
										if domKeyElement == "attributes" {
											doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
												dommAttr, _ := s.Attr(domElement2.(string))
												if dommAttr != "" {
													if domKeyElement2 != "" {
														findRegex, _ := regexp.MatchString("(?i)"+domKeyElement2, dommAttr)
														if findRegex {
															technoTemp := structure.Technologie{}
															technoTemp.Name = technoName
															if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
																technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
															}
															technos = append(technos, technoTemp)
															technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
														}
													} else {
														technoTemp := structure.Technologie{}
														technoTemp.Name = technoName
														if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
															technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
														}
														technos = append(technos, technoTemp)
														technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
													}
												}

											})
										} else {
											var res interface{}
											chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(ctx)
											//fmt.Println(res, "(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()")
											if res == true {
												technoTemp := structure.Technologie{}
												technoTemp.Name = technoName
												if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
													technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
												}
												technos = append(technos, technoTemp)
												technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
											}
										}
									}
								}
							}
						}

					} else {
						for _, domArray := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							doc.Find(domArray.(string)).Each(func(i int, s *goquery.Selection) {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
							})
						}
					}
				}
				if key == "cookies" {

					for cookieTechno, _ := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						//fmt.Println(cookieTechno, cookiesList)
						if len(cookiesList) > 0 {
							for _, cookie := range cookiesList {

								if cookieTechno == cookie.Name {
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technos = append(technos, technoTemp)
									technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
								}
							}
						}

					}
				}
				if key == "scriptSrc" {

					for _, scriptCrc := range srcList {

						if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {
							findRegex, _ := regexp.MatchString("(?i)"+resultGlobal[technoName].(map[string]interface{})[key].(string), scriptCrc)

							if findRegex {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
							}
						} else {

							for _, scriptSrcArray := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {

								finalRegex := strings.ReplaceAll(scriptSrcArray.(string), "/", "\\/")
								findRegex, _ := regexp.MatchString("(?i)"+finalRegex, scriptCrc)
								if findRegex {
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technos = append(technos, technoTemp)
									technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
								}
							}
						}

					}
				}
				if key == "url" {
					if hote.Location != "" {
						if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {
							regex := resultGlobal[technoName].(map[string]interface{})[key].(string)
							findregex, _ := regexp.MatchString("(?i)"+regex, hote.Location)
							if findregex == true {
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
							}
						} else {
							for _, url := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
								findregex, _ := regexp.MatchString("(?i)"+url.(string), hote.Location)
								if findregex == true {
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									technos = append(technos, technoTemp)
									technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
								}
							}
						}
					}

				}

				if key == "html" || key == "text" {
					if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {

						regex := strings.Split(fmt.Sprintf("%v", resultGlobal[technoName].(map[string]interface{})[key]), "\\;")

						findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
						//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
						if findregex == true {
							//fmt.Println(technoName)
							technoTemp := structure.Technologie{}
							technoTemp.Name = technoName
							if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
								technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
							}
							compiledregex := regexp.MustCompile("(?i)" + regex[0])
							regexGroup := compiledregex.FindAllStringSubmatch(body, -1)

							if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
								versionGrp := strings.Split(regex[1], "\\")

								if len(versionGrp) > 1 {
									offset, _ := strconv.Atoi(versionGrp[1])
									//fmt.Println(regexGroup[0][offset])
									technoTemp.Version = regexGroup[0][offset]
								}
							}
							technos = append(technos, technoTemp)
							technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
						}
					} else {
						for _, htmlRegex := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							regex := strings.Split(fmt.Sprintf("%v", htmlRegex), "\\;")

							findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
							//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
							if findregex == true {
								//fmt.Println(technoName)
								technoTemp := structure.Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								compiledregex := regexp.MustCompile("(?i)" + regex[0])
								regexGroup := compiledregex.FindAllStringSubmatch(body, -1)

								if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
									versionGrp := strings.Split(regex[1], "\\")

									if len(versionGrp) > 1 {
										offset, _ := strconv.Atoi(versionGrp[1])
										//fmt.Println(regexGroup[0][offset])
										technoTemp.Version = regexGroup[0][offset]
									}
								}
								technos = append(technos, technoTemp)
								technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
							}
						}
					}
				}
				if key == "meta" {
					for metaKey, metaProperties := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {

						doc.Find("meta[name=\"" + metaKey + "\" i]").Each(func(i int, s *goquery.Selection) {

							if fmt.Sprintf("%T", metaProperties) == "string" {
								metaValue, _ := s.Attr("content")
								regex := strings.Split(fmt.Sprintf("%v", metaProperties), "\\;")
								findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
								//fmt.Println(findregex, metaKey, metaProperties, technoName)
								if findregex == true {
									//fmt.Println(technoName)
									technoTemp := structure.Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									compiledregex := regexp.MustCompile("(?i)" + regex[0])
									regexGroup := compiledregex.FindAllStringSubmatch(metaValue, -1)

									if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
										versionGrp := strings.Split(regex[1], "\\")

										if len(versionGrp) > 1 {
											offset, _ := strconv.Atoi(versionGrp[1])
											//fmt.Println(regexGroup[0][offset])
											technoTemp.Version = regexGroup[0][offset]
										}
									}
									technos = append(technos, technoTemp)
									technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
								}

							} else {
								for _, metaPropertiess := range metaProperties.([]interface{}) {
									metaValue, _ := s.Attr("content")
									regex := strings.Split(fmt.Sprintf("%v", metaPropertiess), "\\;")
									findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
									//fmt.Println(findregex, metaKey, metaPropertiess, technoName)
									if findregex == true {
										//fmt.Println(technoName)
										technoTemp := structure.Technologie{}
										technoTemp.Name = technoName
										if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
											technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
										}
										compiledregex := regexp.MustCompile("(?i)" + regex[0])
										regexGroup := compiledregex.FindAllStringSubmatch(metaValue, -1)

										if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
											versionGrp := strings.Split(regex[1], "\\")

											if len(versionGrp) > 1 {
												offset, _ := strconv.Atoi(versionGrp[1])
												//fmt.Println(regexGroup[0][offset])
												technoTemp.Version = regexGroup[0][offset]
											}
										}
										technos = append(technos, technoTemp)
										technos = technologies.CheckRequired(technoTemp.Name, resultGlobal, technos)
									}
								}
							}
						})
					}
				}

			}
		}
	}
	return technos
}
