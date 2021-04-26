### CR401 - HTTP Basic Authentication Cracker
The CR401 is a simple and fast tool that helps you to crack HTTP basic access authentication with default authentication combinations.
#### Building 
You will need [Golang](https://golang.org/) in your system to build and run this programme and it could be cross-compiled if you need.  
`go build main.go`
#### Usage
-**-plist** path to auth combo file (default "passlist.txt")  
-**-timeout** set http request timeout in seconds. (default 10)  
-**-url** url to attack  