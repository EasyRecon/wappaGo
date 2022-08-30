package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
    "errors"
	"github.com/EasyRecon/wappaGo/analyze"
	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/goccy/go-json"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	pdhttputil "github.com/projectdiscovery/httputil"
	"github.com/remeh/sizedwaitgroup"
)



func Start() {

	options := structure.Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by coma")
	options.Threads = flag.Int("threads", 5, "Number of threads to start recon in same time")
	options.Porttimeout = flag.Int("port-timeout", 1000, "Timeout during port scanning in ms")
	//options.ChromeTimeout = flag.Int("chrome-timeout", 0000, "Timeout during navigation (chrome) in sec")
	options.ChromeThreads = flag.Int("chrome-threads", 5, "Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5)")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	options.AmassInput = flag.Bool("amass-input", false, "Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo")
	options.FollowRedirect = flag.Bool("follow-redirect", false, "Follow redirect to detect technologie")
	flag.Parse()
	var portOpenByIp []structure.PortOpenByIp
	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(*options.Screenshot, os.ModePerm)
			if err != nil {
				log.Println(err)
			}
		}
	}

	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	if len(*options.Resolvers) == 0 {
		*options.Resolvers = "8.8.8.8,1.1.1.1,64.6.64.6,,74.82.42.42,1.0.0.1,8.8.4.4,64.6.65.6,77.88.8.8"
	} 
	fastdialerOpts.BaseResolvers = strings.Split(*options.Resolvers, ",")

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	defer dialer.Close()

	if err != nil {
		fmt.Errorf("could not create resolver cache: %s", err)
	}
	var scanner = bufio.NewScanner(bufio.NewReader(os.Stdin))
	//urls, _ := reader.ReadString('\n')

	optionsChromeCtx := []chromedp.ExecAllocatorOption{}
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DefaultExecAllocatorOptions[:]...)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("headless", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-popup-blocking", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DisableGPU)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-webgl", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("ignore-certificate-errors", true)) // RIP shittyproxy.go
	optionsChromeCtx = append(optionsChromeCtx, chromedp.WindowSize(1400, 900))

	//ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false), chromedp.Flag("disable-gpu", true))...)
	ctxAlloc, cancel1 := chromedp.NewExecAllocator(context.Background(),optionsChromeCtx...)
	defer cancel1()

	ctxAlloc1, cancel := chromedp.NewContext(ctxAlloc)
	//ctxAlloc1, cancel := chromedp.NewContext(context.Background()) 
	defer cancel()

	if err := chromedp.Run(ctxAlloc1); err != nil {
		panic(err)
	}
	folder, errDownload := technologies.DownloadTechnologies()
	if errDownload != nil {
		fmt.Println("error during downbloading techno file")
	}
	defer os.RemoveAll(folder)
	
	resultGlobal := technologies.LoadTechnologiesFiles(folder)

	cdn, err := cdncheck.NewWithCache()
			if err != nil {
			log.Fatal(err)
		}
	var url string
	var ip string
	swg := sizedwaitgroup.New(*options.Threads)
	url=""
	ip=""
	for scanner.Scan() {
		if *options.AmassInput {
				var result map[string]interface{}
				json.Unmarshal([]byte(scanner.Text()), &result)
				url = result["name"].(string)
				ip = result["addresses"].([]interface{})[0].(map[string]interface{})["ip"].(string)
			} else {
				url = scanner.Text()
		}
		swg.Add()
		go func(url string, ip string){
			defer swg.Done()
			
			start(options,portOpenByIp,url,ip, cdn,resultGlobal,dialer,ctxAlloc1)
		}(url,ip)
	}
	swg.Wait()
}


func start(options structure.Options, portOpenByIp []structure.PortOpenByIp,url string,ip string, cdn *cdncheck.Client,resultGlobal map[string]interface{},dialer *fastdialer.Dialer,ctxAlloc1 context.Context) {
	portList := strings.Split(*options.Ports, ",")
	swg1 := sizedwaitgroup.New(len(portList))
	swg := sizedwaitgroup.New(*options.ChromeThreads)
	var CdnName string
	portTemp := portList
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}

	if *options.FollowRedirect {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext:       dialer.Dial,
				DisableKeepAlives: true,
			},
		}

	} else {
		client = &http.Client{
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
		alreadyScanned := lib.CheckIpAlreadyScan(ip, portOpenByIp)

		if alreadyScanned.IP != "" {
			portOpen = alreadyScanned.Open_port
		} else {

			for _, portEnum := range portTemp {
				swg1.Add()
				go func(portEnum string, url string) {
					defer swg1.Done()
					openPort := scanPort("tcp", url, portEnum, *options.Porttimeout)
					if openPort {
						portOpen = append(portOpen, portEnum)
					}
				}(portEnum,url)

			}
			swg1.Wait()
			var tempScanned structure.PortOpenByIp
			tempScanned.IP = ip
			tempScanned.Open_port = portOpen
			portOpenByIp = append(portOpenByIp, tempScanned)

		}

		url = strings.TrimSpace(url)

		for _, port := range portOpen {
			swg.Add()
			go func(port string, url string, portOpen []string, dialer *fastdialer.Dialer, CdnName string) {
				defer swg.Done()
				lauchChrome(url, port, ctxAlloc1, resultGlobal, *options.Screenshot, dialer, portOpen, CdnName, *options.FollowRedirect)
			}(port, url, portOpen, dialer, CdnName)
		}
		swg.Wait()

}

func lauchChrome(urlData string, port string, ctxAlloc1 context.Context, resultGlobal map[string]interface{}, screen string, dialer *fastdialer.Dialer, portOpen []string, CdnName string, followRedirect bool) {
	data := structure.Data{}
	data.Infos.CDN = CdnName
	data.Infos.Data = urlData
	data.Infos.Ports = portOpen
	errorContinue := true

	//u, err := url.Parse(urlData)
	var urlDataPort string
	var resp *structure.Response
	var orginalHost = urlData
	if port != "80" && port != "443" {
		urlDataPort = urlData + ":" + port
	} else {
		urlDataPort = urlData
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}

	if followRedirect {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext:       dialer.Dial,
				DisableKeepAlives: true,
			},
		}

	} else {
		client = &http.Client{
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
	}

	var TempResp structure.Response
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
	dnsData, err := dialer.GetDNSData(orginalHost)
	if dnsData != nil && err == nil {
		data.Infos.Cname = dnsData.CNAME
	}
	if errorContinue {
		if data.Infos.Location != "" {
			urlData = data.Infos.Location
		}
		ctxAlloc1, _ = context.WithTimeout(ctxAlloc1, 30*time.Second)
		cloneCTX, cancel := chromedp.NewContext(ctxAlloc1)
		chromedp.ListenTarget(cloneCTX, func(ev interface{}) {
			if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
				//fmt.Println("closing alert:", ev.Message)
				go func() {
					if err := chromedp.Run(cloneCTX,
						page.HandleJavaScriptDialog(true),
					); err != nil {
						b, err := json.Marshal(data)
						if err != nil {
							fmt.Println("Error:", err)
						}
						fmt.Println(string(b))
						return 
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
			//chromedp.FullScreenshot(&buf, 100),
			chromedp.CaptureScreenshot(&buf),
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
				analyseStruct := analyze.Analyze{resultGlobal, TempResp, srcList, ctx, data.Infos, cookiesList, node, body,[]structure.Technologie{}}

				data.Infos.Technologies = analyseStruct.Run()

				return nil
			}),
		)


		data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
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
			data.Infos.Screenshot =  imgTitle + ".png"
		}
		b, err := json.Marshal(data)

		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println(string(b))
	}
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

// Do http request
func Do(req *http.Request, client *http.Client) (*structure.Response, error) {
	var gzipRetry bool
get_response:
	httpresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var resp structure.Response

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



	return &resp, nil
}

func DefineBasicMetric(data structure.Data, resp *structure.Response) (structure.Data, structure.Response, error) {

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
