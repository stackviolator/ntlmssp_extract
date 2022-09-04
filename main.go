package main

import (
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Format of hash
// [Username]::[Domain]:[NTLM Server Challenge]:[NTProofStr]:[Rest of NTLM Response]

// See if the the 4-8 index of the ApplicationLayer array == the SMB protocol ID
func checkSMBProtocol(arr []byte) bool {
	smb2Id := []byte{254, 83, 77, 66}
	for i, b := range arr {
		if b != smb2Id[i] {
			return false
		}
	}
	return true
}

// Use as interim function to create and feed packets into meat of program
func initPackets(file string) {
	// Open PCAP from file
	if handle, err := pcap.OpenOffline(file); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			appLayer := packet.ApplicationLayer()
			// If there is an application layer in the packet
			if appLayer != nil {
				// TODO: only pulling out long packets (for testing)
				if len(appLayer.Payload()) > 200 {
					fmt.Println("Application Layer found!")
					if checkSMBProtocol(appLayer.Payload()[4:8]) {
						fmt.Println("SMB2 Packet found!")
						fmt.Printf("Length of payload: %d\n", len(appLayer.Payload()))
						// TODO: Print out all the raw bytes (testing)
						for _, b := range appLayer.Payload() {
							// Looking at direct bytes
							fmt.Printf("%x ", byte(b))
						}
					}
					fmt.Println("\n")
				}
			}
		}
	}
}

func arrInSubArray(sub []int, arr []int) bool {
	n := len(sub)
	m := len(arr)
	i, j := 0, 0

	for i < n && j < m {
		if sub[i] == arr[j] {
			i += 1
			j += 1

			if j == m {
				return true
			}
		} else {
			i = i - j + 1
			j = 0
			return false
		}
	}
	return false
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
