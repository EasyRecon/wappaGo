package main

import (
	"flag"
	"os"
	"log"
	"errors"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/cmd"
)

func main() {
	options := structure.Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by coma")
	options.Threads = flag.Int("threads", 5, "Number of threads to start recon in same time")
	options.Porttimeout = flag.Int("port-timeout", 2000, "Timeout during port scanning in ms")
	//options.ChromeTimeout = flag.Int("chrome-timeout", 0000, "Timeout during navigation (chrome) in sec")
	options.ChromeThreads = flag.Int("chrome-threads", 5, "Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5)")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	options.AmassInput = flag.Bool("amass-input", false, "Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo")
	options.FollowRedirect = flag.Bool("follow-redirect", false, "Follow redirect to detect technologie")
	flag.Parse()
	configure(options)
}

func configure(options structure.Options){
	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(*options.Screenshot, os.ModePerm)
			if err != nil {
				log.Println(err)
			}
		}
	}
	c := cmd.Cmd{}
	c.Options = options
	c.Start()
}