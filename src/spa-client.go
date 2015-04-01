package main

import (
	//"os"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"crypto/md5"
	"time"
	"flag"
)

func generatetoken (hash string) (token string) {
	t := time.Now()
	unixtime := (t.Unix())
	currentinterval := unixtime - (unixtime%(60*1))
	clientcounter := unixtime%67+22

	h := md5.New()
	inhash := fmt.Sprintf("%s supersimpleauth %d %d",hash,currentinterval,clientcounter)
	io.WriteString(h,inhash)
	result := fmt.Sprintf("%x", h.Sum(nil))
	return fmt.Sprintf("%d%s",clientcounter,result)
}

func main() {
	key := flag.String("key", "0", "Key is required to authenticate to the spa server, not providing any will fail")
	command := flag.String("cmd", "0", "Command is required to execute something")
	server := flag.String("server", "0", "Parameters as comma seperated list")
	parameters := flag.String("param", "", "Parameters as comma seperated list")
	_ = parameters

	flag.Parse()
	if *key == "0" || *command == "0" || *server == "0" {
		fmt.Printf("Please specify -key, -cmd & -server")
	} else {
		token := generatetoken(*key)
		resp, err := http.PostForm(fmt.Sprintf("http://%s:14041/spa/%s",*server,token),url.Values{"cmd": {*command}, "param": {*parameters}})

		if err != nil {
			fmt.Printf("Didnt manage to post, server incorrect?")
		} else {
			textresp, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Printf("Didnt manage to read answer")
			} else {
				fmt.Printf("Succesfull request send : %s ", textresp)
			}
		}
	}
}