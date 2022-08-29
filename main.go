package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Use as interim function to create and feed packets into meat of program
func initPackets(file string) {
	// Open PCAP from file
	if handle, err := pcap.OpenOffline(file); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				if strings.Contains(appLayer.Payload(), "mike") {

					fmt.Println("Application Layer found")
					fmt.Printf("Application Layer data: %s\n", appLayer.Payload())
					for _, b := range appLayer.Payload() {
						fmt.Printf("%d ", b)
					}
				}
			}
			fmt.Println("")
			fmt.Println("")
		}
	}
}

func main() {
	// Set up the argparse system
	parser := argparse.NewParser("test", "i am testing rn")
	file := parser.String("f", "file", &argparse.Options{Required: true, Help: "Input PCAP file"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// Call packet init sequence
	initPackets(*file)
}
