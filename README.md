### Description

I was developing jsleak during most of my free time for my own need.It is easy-to-use command-line tool designed to uncover secrets and links in JavaScript files or source code. The jsleak was inspired by [Linkfinder](https://github.com/GerbenJavado/LinkFinder) and regexes are collected from multiple sources.  

### Features:

- Discover secrets in JS files such as API keys, tokens, and passwords.
- Identify links in the source code.
- Complete Url Function
- Concurrent processing for scanning of multiple Urls
- Check status code if the url is alive or not

### Instllation
```
go install github.com/channyein1337/jsleak/@latest
```

### Usage
To display help message
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/help.png)
```
jsleak -h
```
Secret Finder
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/secret.png)
```
echo http://testphp.vulnweb.com/ | jsleak -s
```

Link Finder
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/linkfinder.png)
```
echo http://testphp.vulnweb.com/ | jsleak -l
```
Complete Url
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/completeURL.png)
```
echo http://testphp.vulnweb.com/ | jsleak -e
```
Check Status
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/status_code.png)
```
echo http://testphp.vulnweb.com/ | jsleak -c 20 -k
```
You can also use multiple flags 
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/multipleFlags.png)
```
echo http://testphp.vulnweb.com/ | jsleak -c 20 -l -s 
```
Running with Urls
![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/file.png)
```
cat urls.txt | jsleak -l -s -c 30
```
### To Do

- Support scanning local files.
- Support scanning apk files.
- Update Regex.
- Support mulitple user agents.

### Credit and thanks to all the following resources
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/0xsha/GoLinkFinder
