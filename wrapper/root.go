package wrapper

import (
	"errors"
	"log"
	"os"

	"github.com/EasyRecon/wappaGo/cmd"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
)

func StartReconAsync(input []string, wrapperOptions structure.WrapperOptions, results chan structure.Data) {
	c := configureOptions(wrapperOptions)
	c.Input = input

	c.Start(results)
}

func StartReconSync(input []string, wrapperOptions structure.WrapperOptions) []structure.Data {
	c := configureOptions(wrapperOptions)
	c.Input = input

	var resultGlobal []structure.Data

	results := make(chan structure.Data)
	go func() {
		for result := range results {
			resultGlobal = append(resultGlobal, result)
		}
	}()

	c.Start(results)

	return resultGlobal
}

func configureOptions(wrapperOptions structure.WrapperOptions) cmd.Cmd {
	options := structure.Options{}
	falseBool := false

	options.Screenshot = &wrapperOptions.Screenshot
	options.Ports = &wrapperOptions.Ports
	options.Threads = &wrapperOptions.Threads
	options.Report = &falseBool
	options.Porttimeout = &wrapperOptions.Porttimeout
	options.ChromeTimeout = &wrapperOptions.ChromeTimeout
	options.ChromeThreads = &wrapperOptions.ChromeThreads
	options.Resolvers = &wrapperOptions.Resolvers
	options.AmassInput = &falseBool
	options.FollowRedirect = &wrapperOptions.FollowRedirect
	options.Proxy = &wrapperOptions.Proxy

	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(*options.Screenshot, os.ModePerm)
			if err != nil {
				log.Println(err)
			}
		}
	}

	folder, errDownload := technologies.DownloadTechnologies()
	if errDownload != nil {
		log.Println("error during downloading techno file")
	}
	defer os.RemoveAll(folder)

	c := cmd.Cmd{}
	c.ResultGlobal = technologies.LoadTechnologiesFiles(folder)
	c.Options = options

	return c
}
