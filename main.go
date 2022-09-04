package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type SMBPacket struct {
	header_length int
	payload       []byte
	smbPacket     []byte
	blob          []byte
	header        []byte
	protocol_id   []byte
	SSP           []byte
	NTLM_Response []byte
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

// TODO: combine these two functions
func checkSSP(arr []byte) bool {
	// bytes for the string "NTLMSSP"
	ssp_str := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	for i, b := range ssp_str {
		if b != arr[i] {
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

					}
					fmt.Println("\n")
				}
			}
		}
	}
}

/*
	Print a byte array (in practice, a packet) in the format of:
	0000: 00 00 00 00 00 00 00 00
	0010: 00 00 00 00 00 00 00 00
	0020: 00 00 00 00 00 00 00 00
*/
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
	// ApplicationLayer.Payload() includes the NetBIOS junk, which is generally unneeded
	packet.smbPacket = raw_packet.ApplicationLayer().Payload()[4:]
	packet.protocol_id = packet.smbPacket[:3]

	// Header length is directly after protocol id
	packet.header_length = bytesArrToInt(packet.smbPacket[4:5])
	packet.header = packet.smbPacket[:packet.header_length]

	blob_offset := bytesArrToInt(packet.smbPacket[packet.header_length+12 : packet.header_length+14])

	packet.blob = packet.smbPacket[blob_offset:]
	fmt.Println(blob_offset)

	// Check if the NTLMSSP Identifier is "NTLMSSP"
	if checkSSP(packet.smbPacket[packet.header_length+44:]) {
		packet.SSP = packet.blob
		NTLM_Maxlen := bytesArrToInt(packet.SSP[22:24])
		packet.NTLM_Response = packet.SSP[112 : 112+NTLM_Maxlen]
	}

	debugPrint(packet.smbPacket)
	fmt.Println()
	debugPrint(packet.SSP)
	fmt.Println()

	return packet
}

// Convert byte arr to an int, useful for length field in a packet
func bytesArrToInt(arr []byte) int {
	init_len := len(arr)

	if init_len > 8 {
		fmt.Println("Can't take a byte string longer than 8")
	}

	for i := 0; i < 8-init_len; i++ {
		arr = append(arr, 0)
	}

	return int(binary.LittleEndian.Uint64(arr))
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
