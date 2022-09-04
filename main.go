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
	NTProofStr    []byte
	domain        []byte
	username      []byte
}

// Format of hash
// [Username]::[Domain]:[NTLM Server Challenge]:[NTProofStr]:[Rest of NTLM Response]

var smb_protocol_id = []byte{0xf3, 0x53, 0x4d, 0x42}
var NTLMSSP_identifier = []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}

// See if two given byte arrays are equal, used to identify parts of packets
func checkIdBytes(arr []byte, id_arr []byte) bool {
	for i, b := range id_arr {
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
				if len(appLayer.Payload()) > 200 {
					fmt.Println("Application Layer found!")
					smbPacket := makeSMBPacket(packet)
					fmt.Printf("Length: %d\n", len(smbPacket.payload))

					if checkIdBytes(smbPacket.protocol_id, smb_protocol_id) {
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

	// Check if the NTLMSSP Identifier is "NTLMSSP"
	if checkIdBytes(packet.smbPacket[blob_offset+16:], NTLMSSP_identifier) {
		packet.SSP = packet.blob[16:]

		NTLM_Offset := bytesArrToInt(packet.SSP[24:28])
		NTLM_Maxlen := bytesArrToInt(packet.SSP[22:24])
		fmt.Println(NTLM_Offset, NTLM_Maxlen)
		packet.NTLM_Response = packet.SSP[NTLM_Offset : NTLM_Offset+NTLM_Maxlen]
		packet.NTProofStr = packet.NTLM_Response[:16]

		domain_Offset := bytesArrToInt(packet.SSP[32:36])
		domain_Maxlen := bytesArrToInt(packet.SSP[30:32])
		packet.domain = packet.SSP[domain_Offset : domain_Offset+domain_Maxlen]

		username_Offset := bytesArrToInt(packet.SSP[40:44])
		username_Maxlen := bytesArrToInt(packet.SSP[38:40])
		fmt.Println(username_Offset, username_Maxlen)
		packet.username = packet.SSP[username_Offset : username_Offset+username_Maxlen]
	}

	debugPrint(packet.smbPacket)
	fmt.Println()
	debugPrint(packet.SSP)
	fmt.Println()
	debugPrint(packet.domain)
	debugPrint(packet.username)

	return packet
}

// Convert byte arr to an int, useful for length field in a packet
func bytesArrToInt(arr []byte) int {
	init_len := len(arr)
	// When appending 0's to the array later in the function, will overwrite bytes in the og packet array
	var usable []byte
	for _, b := range arr {
		usable = append(usable, b)
	}

	if init_len > 8 {
		fmt.Println("Can't take a byte string longer than 8")
	}

	for i := 0; i < 8-init_len; i++ {
		usable = append(usable, 0)
	}

	return int(binary.LittleEndian.Uint64(usable))
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
