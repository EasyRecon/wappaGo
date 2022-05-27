package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/goccy/go-json"
	"github.com/imdario/mergo"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/cryptoutil"
	"github.com/projectdiscovery/fastdialer/fastdialer"
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
	Host           string        `json:"host"`
	Scheme         string        `json:"scheme"`
	Data           string        `json:"data"`
	Response_time  string        `json:"response_time"`
	Screenshot     string        `json:"screenshot_name,omitempty"`
	Technologies   []Technologie `json:"technologies"`
	Content_length int           `json:"content_length`
	Content_type   string        `json:"content_type`
	IP             string        `json:"ip`
	Cname          []string      `json:"cname,omitempty"`
	CDN            string        `json:"cdn,omitempty"`
}
type Options struct {
	Screenshot  *string
	Ports       *string
	Threads     *int
	Porttimeout *int
	Cdn         *bool
	Resolvers   *string
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

var interrestingKey = []string{"dns", "js", "meta", "text", "dom", "script", "html", "scriptSrc", "headers", "cookies", "url"}

func main() {
	options := Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by coma")
	options.Threads = flag.Int("threads", 10, "Number of threads in same time")
	options.Porttimeout = flag.Int("port-timeout", 1000, "Timeout during port scanning in ms")
	options.Cdn = flag.Bool("cdn", true, "Exclude port scanning on cdn")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	flag.Parse()

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

	resultGlobal := loadTechnologiesFiles()
	swg := sizedwaitgroup.New(*options.Threads)
	portList := strings.Split(*options.Ports, ",")
	cdn, err := cdncheck.NewWithCache()

	for scanner.Scan() {
		var CdnName string
		portTemp := portList
		url := scanner.Text()

		if err != nil {
			log.Fatal(err)
		}

		if *options.Cdn {
			client := &http.Client{
				Timeout: 3 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					DialContext:       dialer.Dial,
					DisableKeepAlives: true,
				},
			}

			client.Get("http://" + url)
			ip := dialer.GetDialedIP(url)
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
		}
		var portOpen []string
		for _, portEnum := range portTemp {

			openPort := scanPort("tcp", url, portEnum, *options.Porttimeout)

			if openPort {
				portOpen = append(portOpen, portEnum)
			}
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
	hote := Host{}
	hote.CDN = CdnName
	hote.Data = urlData
	hote.Ports = portOpen
	errorContinue := true

	//u, err := url.Parse(urlData)
	var resp *http.Response
	var errPlain error
	var errSSL error
	urlDataPort := urlData + ":" + port

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext:       dialer.Dial,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			hote.Location = fmt.Sprintf("%s", req.URL)
			return nil
		},
	}

	resp, errSSL = client.Get("https://" + urlDataPort)
	if errSSL != nil {
		resp, errPlain = client.Get("http://" + urlDataPort)
		if errPlain != nil {
			if errPlain == http.ErrUseLastResponse {

				if (resp.StatusCode == 301 || resp.StatusCode == 302) && len(resp.Header["Location"]) > 0 {
					hote.Location = resp.Header["Location"][0]
				}
			}
			errorContinue = false
		} else {
			if hote.Scheme == "" {
				hote.Scheme = "http"
			}

			urlData = "http://" + urlDataPort
			hote.Host = urlData
		}
	} else {
		if errSSL == http.ErrUseLastResponse {
			if (resp.StatusCode == 301 || resp.StatusCode == 302) && len(resp.Header["Location"]) > 0 {
				hote.Location = resp.Header["Location"][0]
			}
		}
		if hote.Scheme == "" {
			hote.Scheme = "https"
		}
		urlData = "https://" + urlData
		hote.Host = urlData
	}
	ip := dialer.GetDialedIP(hote.Data)
	hote.IP = ip
	dnsData, err := dialer.GetDNSData(urlData)
	if dnsData != nil && err == nil {
		hote.Cname = dnsData.CNAME
	}

	if errorContinue {
		if hote.Location != "" {
			urlData = hote.Location
		}
		body, _ := ioutil.ReadAll(resp.Body)
		//fmt.Println(fmt.Sprintf("%s", body))
		hote.Content_length = len(body)
		if len(resp.Header["Content-Type"]) > 0 {

			hote.Content_type = strings.Split(resp.Header["Content-Type"][0], ";")[0]
		}

		hote.Status_code = resp.StatusCode
		doc, err := goquery.NewDocumentFromReader(resp.Body)
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

		// run task list
		//var res []string
		var buf []byte

		err = chromedp.Run(cloneCTX,
			chromedp.Navigate(urlData),
			chromedp.Title(&hote.Title),
			chromedp.FullScreenshot(&buf, 100),
			chromedp.ActionFunc(func(ctx context.Context) error {
				hote.Technologies = analyze(resultGlobal, resp, srcList, ctx, hote)

				return nil
			}),
		)
		hote.Technologies = dedupTechno(hote.Technologies)
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
			hote.Screenshot = screen + "/" + imgTitle + ".png"
		}

	}
	b, err := json.Marshal(hote)

	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println(string(b))
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

func analyze(resultGlobal map[string]interface{}, resp *http.Response, srcList []string, ctx context.Context, hote Host) []Technologie {
	node, _ := dom.GetDocument().Do(ctx)
	body, _ := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)

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
								chromedp.Evaluate("return "+js+".match(/"+regex[0]+"/gm)[0]", &res)
							} else {
								chromedp.Evaluate("return (typeof "+js+" !== 'undefined' ? true : false)", &res)

							}
							if res != nil && res != false {
								//fmt.Println(js, regex)
								technoTemp := &Technologie{}
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
								hote.Technologies = append(hote.Technologies, *technoTemp)
							}

						} else { // just check if existe
							res := false
							chromedp.Evaluate("return (typeof "+js+" !== 'undefined' ? true : false)", &res)
							if res == true {
								technoTemp := Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								hote.Technologies = append(hote.Technologies, technoTemp)

							}

						}
					}

				}
				if key == "headers" {
					for header, _ := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						//fmt.Println(header, "---------------------", resp.Header)
						for headerName, _ := range resp.Header {
							if strings.ToLower(header) == strings.ToLower(headerName) {
								//headerValue := resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[header]
								if resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName] != "" {
									regex := strings.Split(fmt.Sprintf("%v", resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName]), "\\;")

									findregex, _ := regexp.MatchString("(?i)"+regex[0], resp.Header[headerName][0])
									//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
									if findregex == true {
										//fmt.Println(technoName)
										technoTemp := &Technologie{}
										technoTemp.Name = technoName
										if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
											technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
										}
										compiledregex := regexp.MustCompile("(?i)" + regex[0])
										regexGroup := compiledregex.FindAllStringSubmatch(resp.Header[headerName][0], -1)

										if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
											versionGrp := strings.Split(regex[1], "\\")
											if len(versionGrp) > 1 {
												offset, _ := strconv.Atoi(versionGrp[1])
												//fmt.Println(regexGroup[0][offset])
												technoTemp.Version = regexGroup[0][offset]
											}
										}
										hote.Technologies = append(hote.Technologies, *technoTemp)
									}
								} else {
									technoTemp := &Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									hote.Technologies = append(hote.Technologies, *technoTemp)
								}
							}
						}

					}
				}
				if key == "cookies" {
					cookiesList, _ := network.GetAllCookies().Do(ctx)

					for cookieTechno, _ := range resultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
						//fmt.Println(cookieTechno, cookiesList)
						if len(cookiesList) > 0 {
							for _, cookie := range cookiesList {
								if cookieTechno == cookie.Name {
									technoTemp := &Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									hote.Technologies = append(hote.Technologies, *technoTemp)
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
								technoTemp := &Technologie{}
								technoTemp.Name = technoName
								if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
									technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
								}
								hote.Technologies = append(hote.Technologies, *technoTemp)
							}
						} else {

							for _, scriptSrcArray := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {

								findRegex, _ := regexp.MatchString("(?i)"+scriptSrcArray.(string), scriptCrc)
								if findRegex {
									technoTemp := &Technologie{}
									technoTemp.Name = technoName
									if resultGlobal[technoName].(map[string]interface{})["cpe"] != nil {
										technoTemp.Cpe = resultGlobal[technoName].(map[string]interface{})["cpe"].(string)
									}
									hote.Technologies = append(hote.Technologies, *technoTemp)
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
								technoTemp := &Technologie{}
								technoTemp.Name = technoName
								hote.Technologies = append(hote.Technologies, *technoTemp)
							}
						} else {
							for _, url := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
								findregex, _ := regexp.MatchString("(?i)"+url.(string), hote.Location)
								if findregex == true {
									technoTemp := &Technologie{}
									technoTemp.Name = technoName
									hote.Technologies = append(hote.Technologies, *technoTemp)
								}
							}
						}
					}

				}

				if key == "html" {
					if fmt.Sprintf("%T", resultGlobal[technoName].(map[string]interface{})[key]) == "string" {

						regex := strings.Split(fmt.Sprintf("%v", resultGlobal[technoName].(map[string]interface{})[key]), "\\;")

						findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
						//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
						if findregex == true {
							//fmt.Println(technoName)
							technoTemp := &Technologie{}
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
							hote.Technologies = append(hote.Technologies, *technoTemp)
						}
					} else {
						for _, htmlRegex := range resultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
							regex := strings.Split(fmt.Sprintf("%v", htmlRegex), "\\;")

							findregex, _ := regexp.MatchString("(?i)"+regex[0], body)
							//fmt.Println(findregex, technoName, headerName, resp.Header[headerName][0])
							if findregex == true {
								//fmt.Println(technoName)
								technoTemp := &Technologie{}
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
								hote.Technologies = append(hote.Technologies, *technoTemp)
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
									technoTemp := &Technologie{}
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
									hote.Technologies = append(hote.Technologies, *technoTemp)
								}

							} else {
								for _, metaPropertiess := range metaProperties.([]interface{}) {
									metaValue, _ := s.Attr("content")
									regex := strings.Split(fmt.Sprintf("%v", metaPropertiess), "\\;")
									findregex, _ := regexp.MatchString("(?i)"+regex[0], metaValue)
									//fmt.Println(findregex, metaKey, metaPropertiess, technoName)
									if findregex == true {
										//fmt.Println(technoName)
										technoTemp := &Technologie{}
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
										hote.Technologies = append(hote.Technologies, *technoTemp)
									}
								}
							}
						})
					}
				}

			}
		}
	}
	return hote.Technologies
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
func loadTechnologiesFiles() map[string]interface{} {

	// Open our jsonFile
	var resultGlobal map[string]interface{}
	for _, s := range find("wappalyzer/src/technologies", ".json") {

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
