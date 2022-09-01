package analyze

import (
	"context"
	"strings"
	"github.com/EasyRecon/wappaGo/lib"
	structure "github.com/EasyRecon/wappaGo/structure"
	"github.com/PuerkitoBio/goquery"
	cdp "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/projectdiscovery/retryabledns"

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
	DnsData			*retryabledns.DNSData
}


func (a *Analyze) Run() []structure.Technologie {
	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(a.Body))
	//a.Hote := Host{}
	for technoName, _ := range a.ResultGlobal {
		for key, _ := range a.ResultGlobal[technoName].(map[string]interface{}) {
			if lib.Contains(structure.InterrestingKey, key) {
				if key == "js" {
					a.analyze_js_main(technoName,key)
				}
				if key == "headers" {
					a.analyze_headers_main(technoName,key)
				}
				if key == "dom" {
					a.analyze_dom_main(technoName,key,doc)
				}
				if key == "cookies" && len(a.CookiesList) > 0 {
					a.analyze_cookies_main(technoName,key)
				}
				if key == "scriptSrc" {
					a.analyze_scriptSrc_main(technoName,key)
				}
				if key == "url" {
					a.analyze_url_main(technoName,key)
				}
				if key == "html" || key == "text" {
					a.analyze_html_main(technoName,key)
				}
				if key == "meta" {
					a.analyze_meta_main(technoName,key,doc)
				}
				if key == "dns" {
					a.analyze_dns_main(technoName,key)
				}
			}
		}
	}
	return a.Technos
}





func (a *Analyze) NewTechno(name string)(structure.Technologie){
	technoTemp := structure.Technologie{}
	technoTemp.Name = name
	if a.ResultGlobal[name].(map[string]interface{})["cpe"] != nil {
		technoTemp.Cpe = a.ResultGlobal[name].(map[string]interface{})["cpe"].(string)
	}
	return technoTemp
}