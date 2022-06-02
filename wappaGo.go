package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/goccy/go-json"
	"github.com/imdario/mergo"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/cryptoutil"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	pdhttputil "github.com/projectdiscovery/httputil"
	"github.com/remeh/sizedwaitgroup"
)

type Technologie struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Cpe        string `json:"cpe,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

type Host struct {
	Status_code    int           `json:"status_code"`
	Ports          []string      `json:"ports"`
	Path           string        `json:"path"`
	Location       string        `json:"location,omitempty"`
	Title          string        `json:"title"`
	Scheme         string        `json:"scheme"`
	Data           string        `json:"data"`
	Response_time  time.Duration `json:"response_time"`
	Screenshot     string        `json:"screenshot_name,omitempty"`
	Technologies   []Technologie `json:"technologies"`
	Content_length int           `json:"content_length`
	Content_type   string        `json:"content_type`
	IP             string        `json:"ip`
	Cname          []string      `json:"cname,omitempty"`
	CDN            string        `json:"cdn,omitempty"`
}
type Data struct {
	Url   string `json:"url"`
	Infos Host   `json:"infos"`
}
type Options struct {
	Screenshot  *string
	Ports       *string
	Threads     *int
	Porttimeout *int
	Resolvers   *string
	AmassInput  *bool
}
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *cryptoutil.TLSData

	HTTP2    bool
	Pipeline bool
	Duration time.Duration
}

type PortOpenByIp struct {
	IP        string
	Open_port []string
}

const WappazlyerRoot = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src"
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var interrestingKey = []string{"dns", "js", "meta", "text", "dom", "script", "html", "scriptSrc", "headers", "cookies", "url"}

/*
missing detection:
-dns
-text


*/
func main() {
	options := Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by coma")
	options.Threads = flag.Int("threads", 10, "Number of threads in same time")
	options.Porttimeout = flag.Int("port-timeout", 1000, "Timeout during port scanning in ms")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	options.AmassInput = flag.Bool("amass-input", false, "Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo")
	flag.Parse()
	var portOpenByIp []PortOpenByIp
	if *options.Screenshot != "" {
		file, err := os.Open(*options.Screenshot)
		if err != nil {
			// handle the error and return
		}
		fileinfo, err := os.Stat(*options.Screenshot)
		if err != nil {
			// handle the error and return
		}
		if !fileinfo.IsDir() {
			log.Fatal("error with the screenshot path")
		}
		defer file.Close()
	}

	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	if len(*options.Resolvers) > 0 {
		fastdialerOpts.BaseResolvers = strings.Split(*options.Resolvers, ",")
	}
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	defer dialer.Close()
	if err != nil {
		fmt.Errorf("could not create resolver cache: %s", err)
	}
	var scanner = bufio.NewScanner(bufio.NewReader(os.Stdin))
	//urls, _ := reader.ReadString('\n')

	//ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false), chromedp.Flag("disable-gpu", true))...)
	ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true), chromedp.Flag("disable-gpu", true), chromedp.Flag("disable-webgl", true), chromedp.Flag("disable-popup-blocking", true))...)
	defer cancel()
	ctxAlloc1, cancel := chromedp.NewContext(ctxAlloc)
	//ctxAlloc1, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	if err := chromedp.Run(ctxAlloc1); err != nil {
		panic(err)
	}
	folder, errDownload := downloadTechnologies()
	if errDownload != nil {
		fmt.Println("error during downbloading techno file")
	}
	defer os.RemoveAll(folder)
	resultGlobal := loadTechnologiesFiles(folder)
	swg := sizedwaitgroup.New(*options.Threads)
	portList := strings.Split(*options.Ports, ",")
	cdn, err := cdncheck.NewWithCache()
	var url string
	var ip string
	for scanner.Scan() {
		if *options.AmassInput {
			var result map[string]interface{}
			json.Unmarshal([]byte(scanner.Text()), &result)
			url = result["name"].(string)
			ip = result["addresses"].([]interface{})[0].(map[string]interface{})["ip"].(string)
		} else {
			url = scanner.Text()
		}

		var CdnName string
		portTemp := portList

		if err != nil {
			log.Fatal(err)
		}

		client := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: -1,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext:       dialer.Dial,
				DisableKeepAlives: true,
			},
		}

		if !*options.AmassInput {
			client.Get("http://" + url)
			ip = dialer.GetDialedIP(url)
		}

		isCDN, cdnName, err := cdn.Check(net.ParseIP(ip))
		//fmt.Println(isCDN, ip)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(isCDN)
		if isCDN {
			portTemp = []string{"80", "443"}
			CdnName = cdnName
		}

		var portOpen []string
		alreadyScanned := checkIpAlreadyScan(ip, portOpenByIp)

		if alreadyScanned.IP != "" {
			portOpen = alreadyScanned.Open_port
		} else {
			for _, portEnum := range portTemp {

				openPort := scanPort("tcp", url, portEnum, *options.Porttimeout)

				if openPort {
					portOpen = append(portOpen, portEnum)
				}
			}
			var tempScanned PortOpenByIp
			tempScanned.IP = ip
			tempScanned.Open_port = portOpen
			portOpenByIp = append(portOpenByIp, tempScanned)

		}

		url = strings.TrimSpace(url)

		for _, port := range portOpen {
			swg.Add()
			go func(port string, url string, portOpen []string, dialer *fastdialer.Dialer, CdnName string) {
				defer swg.Done()

				lauchChrome(url, port, ctxAlloc1, resultGlobal, *options.Screenshot, dialer, portOpen, CdnName)

			}(port, url, portOpen, dialer, CdnName)
		}

	}
	swg.Wait()
}

func lauchChrome(urlData string, port string, ctxAlloc1 context.Context, resultGlobal map[string]interface{}, screen string, dialer *fastdialer.Dialer, portOpen []string, CdnName string) {

	data := Data{}
	data.Infos.CDN = CdnName
	data.Infos.Data = urlData
	data.Infos.Ports = portOpen
	errorContinue := true

	//u, err := url.Parse(urlData)
	var urlDataPort string
	var resp *Response
	if port != "80" && port != "443" {
		urlDataPort = urlData + ":" + port
	} else {
		urlDataPort = urlData
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext:       dialer.Dial,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			//data.Infos.Location = fmt.Sprintf("%s", req.URL)

			return http.ErrUseLastResponse

		},
	}

	var TempResp Response
	//resp, errSSL = client.Get("https://" + urlDataPort)
	var errSSL error
	if port != "80" {
		request, _ := http.NewRequest("GET", "https://"+urlDataPort, nil)
		resp, errSSL = Do(request, client)
	}
	if errSSL != nil || port == "80" {
		if port == "443" {
			errorContinue = false
		} else {
			request, _ := http.NewRequest("GET", "http://"+urlDataPort, nil)
			resp, errPlain := Do(request, client)
			if errPlain != nil || resp == nil {

				errorContinue = false
			} else {
				data, TempResp, _ = DefineBasicMetric(data, resp)
				if data.Infos.Scheme == "" {
					data.Infos.Scheme = "http"
				}
				urlData = "http://" + urlDataPort
				data.Url = urlData
			}
		}
	} else {
		data, TempResp, _ = DefineBasicMetric(data, resp)
		if data.Infos.Scheme == "" {
			data.Infos.Scheme = "https"
		}
		urlData = "https://" + urlDataPort
		data.Url = urlData
	}
	ip := dialer.GetDialedIP(data.Infos.Data)
	data.Infos.IP = ip
	dnsData, err := dialer.GetDNSData(urlData)
	if dnsData != nil && err == nil {
		data.Infos.Cname = dnsData.CNAME
	}

	if errorContinue {
		if data.Infos.Location != "" {
			urlData = data.Infos.Location
		}

		cloneCTX, cancel := chromedp.NewContext(ctxAlloc1)
		chromedp.ListenTarget(cloneCTX, func(ev interface{}) {
			if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
				//fmt.Println("closing alert:", ev.Message)
				go func() {
					if err := chromedp.Run(cloneCTX,
						page.HandleJavaScriptDialog(true),
					); err != nil {
						panic(err)
					}
				}()
			}
		})
		defer cancel()
		// run task list
		//var res []string
		var buf []byte
		err = chromedp.Run(cloneCTX,
			chromedp.Navigate(urlData),
			chromedp.Title(&data.Infos.Title),
			chromedp.FullScreenshot(&buf, 100),
			chromedp.ActionFunc(func(ctx context.Context) error {

				cookiesList, _ := network.GetCookies().Do(ctx)
				node, _ := dom.GetDocument().Do(ctx)
				body, _ := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)

				reader := strings.NewReader(body)
				doc, err := goquery.NewDocumentFromReader(reader)

				if err != nil {
					log.Fatal(err)
				}
				var srcList []string
				doc.Find("script").Each(func(i int, s *goquery.Selection) {
					srcLink, exist := s.Attr("src")

					if exist {

						//fmt.Println(srcList, srcLink)
						srcList = append(srcList, srcLink)
					}
				})
				data.Infos.Technologies = analyze(resultGlobal, TempResp, srcList, ctx, data.Infos, cookiesList, node, body)

				return nil
			}),
		)
		data.Infos.Technologies = dedupTechno(data.Infos.Technologies)
		if screen != "" && len(buf) > 0 {
			imgTitle := strings.Replace(urlData, ":", "_", -1)
			imgTitle = strings.Replace(imgTitle, "/", "", -1)
			imgTitle = strings.Replace(imgTitle, ".", "_", -1)
			//fmt.Println(screen + "/" + imgTitle + ".png")
			file, _ := os.OpenFile(
				screen+"/"+imgTitle+".png",
				os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
				0666,
			)
			file.Write(buf)
			file.Close()
			data.Infos.Screenshot = screen + "/" + imgTitle + ".png"
		}
		b, err := json.Marshal(data)

		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println(string(b))
	}
}
func dedupTechno(technologies []Technologie) []Technologie {
	var output []Technologie
	add := true
	for _, tech := range technologies {
		add = true
		for _, checkTech := range output {
			if checkTech == tech {
				add = false
			} else {
				if checkTech.Name == tech.Name && tech.Version == "" {
					add = false
				}
			}
		}
		if add {
			output = append(output, tech)
		}
	}
	return output
}

func analyze(resultGlobal map[string]interface{}, resp Response, srcList []string, ctx context.Context, hote Host, cookiesList []*network.Cookie, node *cdp.Node, body string) []Technologie {

	var technologies []Technologie
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(body))
	//hote := Host{}
	for technoName, _ := range resultGlobal {
		for key, _ := range resultGlobal[technoName].(map[string]interface{}) {
			if contains(interrestingKey, key) {
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
								technoTemp := Technologie{}
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
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
							}

						} else { // just check if existe
							var res interface{}
							chromedp.Evaluate("return (typeof "+js+" !== 'undefined' ? true : false)", &res).Do(ctx)
							if res == true {
								technoTemp := Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)

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
										technoTemp := Technologie{}

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
										technologies = append(technologies, technoTemp)
										technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
									}
								} else {
									technoTemp := Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technologies = append(technologies, technoTemp)
									technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
								}
							}
						}

					}
				}
				if key == "dom" {

					if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {
						doc.Find(resultGlobal[technoName].(map[string]interface{})[key].(string)).Each(func(i int, s *goquery.Selection) {
							technoTemp := Technologie{}
							technoTemp.Name = technoName
							if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
								technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
							}
							technologies = append(technologies, technoTemp)
							technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
						})

					} else if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "map[string]interface {}" {

						for domKey, domArray := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {

							for domKeyElement, domElement := range domArray.(map[string]interface{}) {
								if fmt.Sprintf("%T", domElement) == "string" {
									doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
										if domElement == "" {
											technoTemp := Technologie{}
											technoTemp.Name = technoName
											if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
												technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
											}
											technologies = append(technologies, technoTemp)
											technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
										} else {
											regex := strings.Split(domElement.(string), "\\;")

											findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
											if findregex {
												//fmt.Println(technoName)
												technoTemp := Technologie{}
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
												technologies = append(technologies, technoTemp)
												technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
															technoTemp := Technologie{}
															technoTemp.Name = technoName
															if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
																technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
															}
															technologies = append(technologies, technoTemp)
															technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
														}
													} else {
														technoTemp := Technologie{}
														technoTemp.Name = technoName
														if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
															technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
														}
														technologies = append(technologies, technoTemp)
														technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
													}
												}

											})
										} else {
											var res interface{}
											chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(ctx)
											//fmt.Println(res, "(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()")
											if res == true {
												technoTemp := Technologie{}
												technoTemp.Name = technoName
												if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
													technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
												}
												technologies = append(technologies, technoTemp)
												technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
											}
										}
									}
								}
							}
						}

					} else {
						for _, domArray := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							doc.Find(domArray.(string)).Each(func(i int, s *goquery.Selection) {
								technoTemp := Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
									technoTemp := Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technologies = append(technologies, technoTemp)
									technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
								technoTemp := Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
							}
						} else {

							for _, scriptSrcArray := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {

								finalRegex := strings.ReplaceAll(scriptSrcArray.(string), "/", "\\/")
								findRegex, _ := regexp.MatchString("(?i)"+finalRegex, scriptCrc)
								if findRegex {
									technoTemp := Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									technologies = append(technologies, technoTemp)
									technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
								technoTemp := Technologie{}
								technoTemp.Name = technoName
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
							}
						} else {
							for _, url := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
								findregex, _ := regexp.MatchString("(?i)"+url.(string), hote.Location)
								if findregex == true {
									technoTemp := Technologie{}
									technoTemp.Name = technoName
									technologies = append(technologies, technoTemp)
									technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
							technoTemp := Technologie{}
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
							technologies = append(technologies, technoTemp)
							technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
						}
					} else {
						for _, htmlRegex := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							regex := strings.Split(fmt.Sprintf("%v", htmlRegex), "\\;")

							findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
							//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
							if findregex == true {
								//fmt.Println(technoName)
								technoTemp := Technologie{}
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
								technologies = append(technologies, technoTemp)
								technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
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
									technoTemp := Technologie{}
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
									technologies = append(technologies, technoTemp)
									technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
								}

							} else {
								for _, metaPropertiess := range metaProperties.([]interface{}) {
									metaValue, _ := s.Attr("content")
									regex := strings.Split(fmt.Sprintf("%v", metaPropertiess), "\\;")
									findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
									//fmt.Println(findregex, metaKey, metaPropertiess, technoName)
									if findregex == true {
										//fmt.Println(technoName)
										technoTemp := Technologie{}
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
										technologies = append(technologies, technoTemp)
										technologies = checkRequired(technoTemp.Name, resultGlobal, technologies)
									}
								}
							}
						})
					}
				}

			}
		}
	}
	return technologies
}
func scanPort(protocol, hostname string, port string, portTimeout int) bool {
	address := hostname + ":" + port
	conn, err := net.DialTimeout(protocol, address, time.Duration(portTimeout)*time.Millisecond)

	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
func loadTechnologiesFiles(folder string) map[string]interface{} {

	// Open our jsonFile
	var resultGlobal map[string]interface{}
	for _, s := range find(folder, ".json") {

		jsonFile, err := os.Open(s)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}

		json.Unmarshal([]byte(byteValue), &result)
		mergo.Merge(&resultGlobal, result)

	}
	return resultGlobal
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getKey(array map[string]interface{}) []string {
	k := make([]string, len(array))
	i := 0
	for s, _ := range array {
		k[i] = s
		i++
	}
	return k
}
func find(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}

// Do http request
func Do(req *http.Request, client *http.Client) (*Response, error) {
	timeStart := time.Now()

	var gzipRetry bool
get_response:
	httpresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var resp Response

	resp.Headers = httpresp.Header.Clone()

	// httputil.DumpResponse does not handle websockets
	headers, rawResp, err := pdhttputil.DumpResponseHeadersAndRaw(httpresp)
	if err != nil {
		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			goto get_response
		}

		return nil, err

	}
	resp.Raw = string(rawResp)
	resp.RawHeaders = string(headers)

	var respbody []byte
	// websockets don't have a readable body
	if httpresp.StatusCode != http.StatusSwitchingProtocols {
		var err error
		respbody, err = ioutil.ReadAll(io.LimitReader(httpresp.Body, 4096))
		if err != nil {

			return nil, err
		}
	}

	closeErr := httpresp.Body.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	respbodystr := string(respbody)

	// if content length is not defined
	if resp.ContentLength <= 0 {
		// check if it's in the header and convert to int
		if contentLength, ok := resp.Headers["Content-Length"]; ok {
			contentLengthInt, _ := strconv.Atoi(strings.Join(contentLength, ""))
			resp.ContentLength = contentLengthInt
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbodystr) > 0 {
			resp.ContentLength = utf8.RuneCountInString(respbodystr)
		}
	}

	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	// number of words
	resp.Words = len(strings.Split(respbodystr, " "))
	// number of lines
	resp.Lines = len(strings.Split(respbodystr, "\n"))

	resp.Duration = time.Since(timeStart)

	return &resp, nil
}

func DefineBasicMetric(data Data, resp *Response) (Data, Response, error) {

	if (resp.StatusCode == 301 || resp.StatusCode == 302) && len(resp.Headers["Location"]) > 0 {
		data.Infos.Location = resp.Headers["Location"][0]
	}
	if len(resp.Headers["Content-Type"]) > 0 {
		data.Infos.Content_type = strings.Split(resp.Headers["Content-Type"][0], ";")[0]
	}
	data.Infos.Response_time = resp.Duration
	data.Infos.Content_length = resp.ContentLength
	data.Infos.Status_code = resp.StatusCode
	return data, *resp, nil
}

func checkRequired(technoName string, technoList map[string]interface{}, tech []Technologie) []Technologie {
	for name, _ := range technoList[technoName].(map[string]interface{}) {
		if name == "requires" {
			if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["requires"]) == "string" {
				technoTemp := Technologie{}
				technoTemp.Name = technoList[technoName].(map[string]interface{})["requires"].(string)
				tech = append(tech, technoTemp)
			} else {
				if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["requires"].(map[string]interface{})) == "string" {
					technoTemp := Technologie{}
					technoTemp.Name = technoList[technoName].(map[string]interface{})["requires"].(string)
					tech = append(tech, technoTemp)
				} else {
					for req, _ := range technoList[technoName].(map[string]interface{})["requires"].(map[string]interface{}) {
						technoTemp := Technologie{}
						technoTemp.Name = req
						tech = append(tech, technoTemp)
					}
				}

			}
		}
	}
	return tech
}

func downloadTechnologies() (string, error) {
	files := []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	folder := RandStringBytes(20)
	_ = os.Mkdir(folder, 0666)
	for _, f := range files {
		url := fmt.Sprintf("%v/technologies/%v.json", WappazlyerRoot, f)
		resp, err := http.Get(url)
		if err != nil {
			return "", err
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		file, _ := os.OpenFile(
			folder+"/"+f+".json",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		file.Write(body)
		file.Close()

	}
	return folder, nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
func checkIpAlreadyScan(ip string, list []PortOpenByIp) PortOpenByIp {
	for _, ipScanned := range list {
		if ip == ipScanned.IP {
			return ipScanned
		}
	}
	return PortOpenByIp{}
}
