### Description

I was developing jsleak during most of my free time for my own need.It is easy-to-use command-line tool designed to uncover secrets and links in JavaScript files or source code. The jsleak was inspired by [Linkfinder](https://github.com/GerbenJavado/LinkFinder) and regexes are collected from multiple sources.  

### Features:

- Discover secrets in JS files such as API keys, tokens, and passwords.
- Identify links in the source code.
- Complete Url Function
- Concurrent processing for scanning of multiple Urls
- Check status code if the url is alive or not

### Latest Update
Jsleak now supports regex patterns from secrets-patterns-db [https://github.com/mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db).

If you want to use your own custom regex patterns, you can place them in a YAML file following the template below. 
```
patterns:
  - pattern:
      name: Amazon MWS Auth Token
      regex: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
      confidence: low
```


### Installation
If you are using old version of golang (go 1.15, 1.16) , use the following command to install jsleak.
```
go get github.com/channyein1337/jsleak
```

If you are using latest version of  go (1.17+) , use the following command to install.

```
go install github.com/channyein1337/jsleak@latest
```


### Usage

Choose a YAML file from the secrets-patterns-db. If you’re not sure which one to pick, consider using: [https://raw.githubusercontent.com/mazen160/secrets-patterns-db/refs/heads/master/datasets/trufflehog-v3.yaml](https://raw.githubusercontent.com/mazen160/secrets-patterns-db/refs/heads/master/datasets/trufflehog-v3.yaml)

Run jsleak with Your Selected Regex File
```
echo "http://testphp.vulnweb.com/" | jsleak -t trufflehog-v3.yaml -s
```

To display help message

```
jsleak -h
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/help.png)

Secret Finder

```
echo http://testphp.vulnweb.com/ | jsleak  -t secret.yaml -s
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/secret.png)


Link Finder

```
echo http://testphp.vulnweb.com/ | jsleak -l
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/linkfinder.png)

Complete Url

```
echo http://testphp.vulnweb.com/ | jsleak -e
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/completeURL.png)

Check Status

```
echo http://testphp.vulnweb.com/ | jsleak -c 20 -k
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/status_code.png)

You can also use multiple flags 

```
echo http://testphp.vulnweb.com/ | jsleak -c 20 -l -s 
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/multipleFlags.png)

Running with Urls

```
cat urls.txt | jsleak -l -s -c 30
```

![](https://raw.githubusercontent.com/channyein1337/jsleak/main/images/file.png)

### To Do

- Scan secret on completeURL with 200 response.
- Add Version flag.
- Support scanning local files.
- Support scanning apk files.
- Update Regex.
- Support mulitple user agents.
- Support color output


### Credit and thanks to all the following resources
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/0xsha/GoLinkFinder
