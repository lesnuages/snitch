package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/lesnuages/snitch/pkg/snitch"
)

func burned(res *snitch.ScanResult) {
	log.Printf("[!] File %s has been seen on Virus Total on %s\n", res.Sample.Name(), res.LastSeen.String())
}

func parseDir(dirPath string, sn *snitch.Snitch) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, fInfo := range files {
		if !fInfo.IsDir() {
			fPath := fmt.Sprintf("%s/%s", dirPath, fInfo.Name())
			data, err := ioutil.ReadFile(fPath)
			if err != nil {
				log.Fatal(err)
			}
			sum := md5.Sum(data)
			hash := hex.EncodeToString(sum[:])
			log.Printf("Adding %s (%s) to the list\n", fInfo.Name(), hash)
			sn.Add(fInfo.Name(), hash)
		}
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Please provide a valid path")
	}
	vtKey := os.Getenv("VT_API_KEY")
	if vtKey == "" {
		log.Fatal("plese provide a valid API key")
	}
	sn := snitch.WithHandleFlagged(burned)
	sn.AddScanner(snitch.NewVTScanner(vtKey, 4, "Virus Total"))
	sn.Start()
	parseDir(os.Args[1], sn)
	log.Println("[*] Let's sleep for a while ...")
	for {
		time.Sleep(10 * time.Second)
		log.Println("sleeping")
	}
	// sn.Stop()
}
