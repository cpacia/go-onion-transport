package oniontransport

import (
	"context"
	"fmt"
	"github.com/cretz/bine/tor"
	"github.com/ipsn/go-libtor"
	"log"
	"testing"
	"time"
)

func TestNewTorResover(t *testing.T) {
	torClient, err := tor.Start(nil, &tor.StartConf{
		ProcessCreator:  libtor.Creator,
		DataDir:         "/home/chris/.openbazaar",
		NoAutoSocksPort: true,
		EnableNetwork:   true,
		NoHush:          true,
		ExtraArgs:       []string{"--DNSPort", "2121"},
	})
	if err != nil {
		log.Fatal(err)
	}

	defer torClient.Close()
	time.Sleep(time.Second * 5)

	r := NewTorResover("")
	/*addr, err := multiaddr.NewMultiaddr("/dns4/ipfs.io")
	if err != nil {
		t.Fatal(err)
	}*/
	fmt.Println(r.Backend.LookupTXT(context.Background(), "ipfs.io"))
}
