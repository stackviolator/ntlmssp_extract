package main

import (
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type SMBPacket struct {
	header_length int
	payload       []byte
	header        []byte
	protocol_id   []byte
	SSP           []byte
}

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
				if len(appLayer.Payload()) > 550 {
					fmt.Println("Application Layer found!")
					smbPacket := makeSMBPacket(packet)
					fmt.Printf("Length: %d\n", len(smbPacket.payload))

					if checkSMBProtocol(smbPacket.protocol_id) {
						fmt.Println("SMB2 Packet found!")

						debugPrint(packet.Data())

						for i := 0; i < 9; i++ {
							fmt.Printf("%x ", smbPacket.payload[80+i])
						}

						fmt.Println("\n")

						debugPrint(smbPacket.ssp)

					}
					fmt.Println("\n")
				}
			}
		}
	}
}

func debugPrint(payload []byte) {
	for i := 0; i <= (len(payload) / 16); i++ {
		fmt.Printf("%4x: ", i)
		for j := 0; j < 16; j++ {
			if (16*i)+j < len(payload) {
				fmt.Printf("%2x ", payload[(16*i)+j])
			}
		}
		fmt.Println("")
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

func makeSMBPacket(raw_packet gopacket.Packet) SMBPacket {
	var packet SMBPacket

	// Place the entire raw packet
	packet.payload = raw_packet.Data()
	packet.protocol_id = raw_packet.ApplicationLayer().Payload()[4:7]
	// Header length is directly after protocol id
	packet.header_length = int(raw_packet.ApplicationLayer().Payload()[8])
	packet.header = raw_packet.ApplicationLayer().Payload()[:packet.header_length]
	packet.SSP = raw_packet.ApplicationLayer().Payload()[packet.header_length+44:]

	return packet
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
