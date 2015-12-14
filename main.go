package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
)

var (
	addr    = flag.String("addr", ":8181", "http service address:port")
	secret  = flag.String("secret", "", "HMACed secret in POST header")
	logfn   = flag.String("logfn", "", "full path to log file")
	runmake = flag.Bool("runmake", false, "run make all after git pull")
	LOG     *log.Logger
)

func gitPullHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/git/pull" {
		http.Error(w, "Not found", 404)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	mMACraw := []byte(r.Header.Get("X-Hub-Signature"))
	mMAC := make([]byte, 20)
	n, err := hex.Decode(mMAC, mMACraw[5:]) // trim 'sha1=' off header before decoding
	if err != nil || n != 20 {
		LOG.Println(n)
		LOG.Println(err)
		return
	}
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		LOG.Println(err)
		return
	}
	key := []byte(*secret)
	ok := CheckMAC(payload, mMAC, key)
	if !ok {
		LOG.Println("HMAC not ok")
		return
	}
	LOG.Println("HMAC ok! Init pull request.")
	cmd := exec.Command("git", "pull")
	err = cmd.Run()
	if err != nil {
		LOG.Println(err)
	}

	if !*runmake {
		return
	}

	cmd = exec.Command("make", "all")
	err = cmd.Run()
	if err != nil {
		LOG.Println(err)
	}

}

func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func main() {
	flag.Parse()
	logfp, err := os.OpenFile(*logfn, os.O_WRONLY, os.ModeAppend)
	defer logfp.Close()
	if err != nil {
		log.Fatalln(err)
	}
	LOG = log.New(logfp, "github: ", log.Lshortfile)

	http.HandleFunc("/git/pull", gitPullHandler)

	err = http.ListenAndServe(*addr, nil)
	if err != nil {
		LOG.Fatalf("%s\n", err)
	}
	for {
	}
}
