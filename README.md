This tool is created to assemble different tools like https, naabu, gowitness and add a detection of the headless technology of chrome instead of httpx.

## Why

Because many tools need a chrome headless session. If you use several tools, for the same url, you have to open 2 chrome sessions, with this tool, only one session is needed.

## Exemples


Two usage method :

cat directly text file (one domain per ligne) on wappaGo
```
cat domain.txt | ./wappaGo
```



else you can directly pipe wappaGo on Amass JSON output like :

```
amass enum -d exemple.com -json out.json | ./wappaGo -amass-input
```
## Todo

increase speed
code refacto


## Thank's

This tool uses several projectdiscovery libraries and is inspired by these tools.