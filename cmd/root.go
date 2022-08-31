package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
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
type Cmd struct {
	ChromeCtx 		context.Context
	Dialer 			*fastdialer.Dialer
	ResultGlobal 	map[string]interface{}
	Cdn 			*cdncheck.Client
	Options 		structure.Options
	PortOpenByIP    []structure.PortOpenByIp
	HttpClient		*http.Client
}


func (c *Cmd)Start() {
	var err error
	c.Dialer = c.InitDialer()
	defer c.Dialer.Close()
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
	c.ChromeCtx = ctxAlloc1
	defer cancel()

	if err := chromedp.Run(c.ChromeCtx); err != nil {
		panic(err)
	}


	c.Cdn, err = cdncheck.NewWithCache()
			if err != nil {
			log.Fatal(err)
		}
	var url string
	var ip string
	swg := sizedwaitgroup.New(*c.Options.Threads)
	url=""
	ip=""
	for scanner.Scan() {
		if *c.Options.AmassInput {
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
			c.startPortScan(url,ip)
		}(url,ip)
	}
	swg.Wait()
}


func (c *Cmd)startPortScan(url string,ip string) {
	portList := strings.Split(*c.Options.Ports, ",")
	swg1 := sizedwaitgroup.New(50)
	swg := sizedwaitgroup.New(*c.Options.ChromeThreads)
	var CdnName string
	portTemp := portList
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		if !*c.Options.AmassInput {
			ip = c.getIP(url)
		}
		isCDN, cdnName, err := c.Cdn.Check(net.ParseIP(ip))
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
		alreadyScanned := lib.CheckIpAlreadyScan(ip, c.PortOpenByIP)
		if alreadyScanned.IP != "" {
			portOpen = alreadyScanned.Open_port
		} else {
			for _, portEnum := range portTemp {
				swg1.Add()
				go func(portEnum string, url string) {
					defer swg1.Done()
					openPort := c.scanPort("tcp", url, portEnum, *c.Options.Porttimeout)
					if openPort {
						portOpen = append(portOpen, portEnum)
					}
				}(portEnum,url)
			}
			swg1.Wait()
			var tempScanned structure.PortOpenByIp
			tempScanned.IP = ip
			tempScanned.Open_port = portOpen
			c.PortOpenByIP = append(c.PortOpenByIP, tempScanned)
		}
		url = strings.TrimSpace(url)
		for _, port := range portOpen {
			swg.Add()
			go func(port string, url string, portOpen []string, CdnName string) {
				defer swg.Done()
				c.getWrapper(url, port, portOpen, CdnName)
			}(port, url, portOpen, CdnName)
		}
		swg.Wait()
}

func (c *Cmd)getWrapper(urlData string, port string,portOpen []string, CdnName string) {
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
	client := c.getClientCtx()
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
				data, TempResp, _ = c.DefineBasicMetric(data, resp)
				if data.Infos.Scheme == "" {
					data.Infos.Scheme = "http"
				}
				urlData = "http://" + urlDataPort
				data.Url = urlData
			}
		}
	} else {
		data, TempResp, _ = c.DefineBasicMetric(data, resp)
		if data.Infos.Scheme == "" {
			data.Infos.Scheme = "https"
		}
		urlData = "https://" + urlDataPort
		data.Url = urlData
	}
	ip := c.Dialer.GetDialedIP(data.Infos.Data)
	data.Infos.IP = ip
	dnsData, err := c.Dialer.GetDNSData(orginalHost)
	if dnsData != nil && err == nil {
		data.Infos.Cname = dnsData.CNAME
	}
	if errorContinue {
		c.lauchChrome(TempResp ,data, urlData , port,portOpen , CdnName)
	}
}
func (c *Cmd)lauchChrome(TempResp structure.Response,data structure.Data, urlData string, port string,portOpen []string, CdnName string) {
	    var err error
		if data.Infos.Location != "" {
			urlData = data.Infos.Location
		}
		ctxAlloc1, _ := context.WithTimeout(c.ChromeCtx, 60*time.Second)
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
				analyseStruct := analyze.Analyze{c.ResultGlobal, TempResp, srcList, ctx, data.Infos, cookiesList, node, body,[]structure.Technologie{}}

				data.Infos.Technologies = analyseStruct.Run()

				return nil
			}),
		)


		data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
		if *c.Options.Screenshot != "" && len(buf) > 0 {
			imgTitle := strings.Replace(urlData, ":", "_", -1)
			imgTitle = strings.Replace(imgTitle, "/", "", -1)
			imgTitle = strings.Replace(imgTitle, ".", "_", -1)
			//fmt.Println(screen + "/" + imgTitle + ".png")
			file, _ := os.OpenFile(
				*c.Options.Screenshot +"/"+imgTitle+".png",
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

func (c *Cmd)scanPort(protocol, hostname string, port string, portTimeout int) bool {
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


func (c *Cmd)InitDialer()(*fastdialer.Dialer){
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	if len(*c.Options.Resolvers) == 0 {
		*c.Options.Resolvers = "8.8.8.8,1.1.1.1,64.6.64.6,,74.82.42.42,1.0.0.1,8.8.4.4,64.6.65.6,77.88.8.8"
	} 
	fastdialerOpts.BaseResolvers = strings.Split(*c.Options.Resolvers, ",")

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		fmt.Errorf("could not create resolver cache: %s", err)
	}
	return dialer
}

func (c *Cmd)getClientCtx(){
	if c.HttpClient == (&http.Client{}) {
		c.HttpClient = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext:       c.Dialer.Dial,
				DisableKeepAlives: true,
			},
		}
		if !*c.Options.FollowRedirect {
			c.HttpClient.CheckRedirect= func(req *http.Request, via []*http.Request) error {
				//data.Infos.Location = fmt.Sprintf("%s", req.URL)
				return http.ErrUseLastResponse
			}
		} 
	}
}
func (c *Cmd)getIP(url string)(string){
	c.getClientCtx()
	c.HttpClient.Get("http://" + url)
	ip := c.Dialer.GetDialedIP(url)
	return ip
}



func (c *Cmd)DefineBasicMetric(data structure.Data, resp *structure.Response) (structure.Data, structure.Response, error) {

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
