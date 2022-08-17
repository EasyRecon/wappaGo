# WappaGo

<p align="center">  
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r"><img src="https://img.shields.io/badge/release-v0.0.2-informational"></a>
    <a href="https://github.com/easyrecon/wappago/issues" target="_blank"><img src="https://img.shields.io/github/issues/easyrecon/wappago?color=blue" /></a>
</p>

<p align="center">  
    <a href="https://codeclimate.com/github/EasyRecon/wappaGo"><img src="https://codeclimate.com/github/EasyRecon/wappaGo.png"></a>
</p>

<p align="center">
  <a href="#about">About WappaGo</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a>
</p>

# About
WappaGo has been developed to assemble different features from tools like [HTTPX](https://github.com/projectdiscovery/httpx), [Naabu](https://github.com/projectdiscovery/naabu), [GoWitness](https://github.com/sensepost/gowitness) and [Wappalyzer](https://github.com/wappalyzer/wappalyzer).
To allow an efficient detection of technologies, it is necessary to open a browser and in order to avoid opening a browser for each target, WappaGo opens only one browser and uses the system of pages which allows to consume less resources and to carry out an analysis much more quickly.

# Installation

Download the latest [release](https://github.com/EasyRecon/wappaGo/releases)  or compile by yourself :

```bash
git clone https://github.com/EasyRecon/wappaGo
cd wappaGo && go build wappaGo.go
```

**Note :** _wappaGo requires Chrome to be present on the system_

# Usage
```
Usage of ./wappaGo:
  -amass-input
    	Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo
  -follow-redirect
        Follow redirect to detect technologie
  -port-timeout int
    	Timeout during port scanning in ms (default 1000)
  -ports string
    	port want to scan separated by coma (default "80,443")
  -resolvers string
    	Use specifique resolver separated by comma
  -screenshot string
    	path to screenshot if empty no screenshot
  -threads-chrome int
    	Number of threads to detect technology (Chrome) in same time (default 10)
  -threads-ports int
    	Number of threads to scan port in same time (default 60)
```

You can either use wappaGo from a file containing a list of domains
```bash
cat domain.txt | ./wappaGo
```

or from an Amass output  (preferred)

```bash
amass enum -d example.com -ipv4 -json out.json
cat out.json | ./wappaGo -amass-input
```

## Todo

  - Increase speed
  - Code refacto


## Thank's

This tool uses several [ProjectDiscovery](https://github.com/projectdiscovery) libraries
