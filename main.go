// Note to future Josh from past Josh - when debugging, use hex.Dump([]byte)

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	req_type      []byte
	response      bool
	struct_len    int
	blob          []byte
	header        []byte
	protocol_id   []byte
	SSP           []byte
	NTLM_Response []byte
	NTProofStr    []byte
	rest_of_NTLM  []byte
	domain        []byte
	username      []byte
	NT_challenge  []byte
}

var smb_protocol_id = []byte{0xfe, 0x53, 0x4d, 0x42}
var NTLMSSP_identifier = []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
var NTLMSSP_AUTH = []byte{03, 00, 00, 00}
var NTLMSSP_CHALLENGE = []byte{02, 00, 00, 00}

// See if two given byte arrays are equal, used to identify parts of packets
func checkIdBytes(arr []byte, id_arr []byte) bool {
	for i, b := range id_arr {
		if b != arr[i] {
			return false
		}
	}
	return true
}

// Parse pcap to pull out SMB2 packets, and add to an array
func initPackets(file string) {
	var smb_packets []SMBPacket
	// Open PCAP from file
	if handle, err := pcap.OpenOffline(file); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			appLayer := packet.ApplicationLayer()
			// If there is an application layer in the packet
			if appLayer != nil {
				if len(appLayer.Payload()) > 0 {
					if checkIdBytes(appLayer.Payload()[4:8], smb_protocol_id) {
						smbPacket := makeSMBPacket(packet)
						smb_packets = append(smb_packets, smbPacket)
					}
				}
			}
		}
	}
	extract_hashes(smb_packets)
}

// Format of hash
// [Username]::[Domain]:[NTLM Server Challenge]:[NTProofStr]:[Rest of NTLM Response]
func extract_hashes(packets []SMBPacket) {
	for i, p := range packets {
		if p.NTLM_Response != nil {
			fmt.Println("Hash found")
			fmt.Printf(
				"%s::%s:%s:%s:%s",
				p.username,
				p.domain,
				hex.EncodeToString(packets[i-1].NT_challenge),
				hex.EncodeToString(p.NTProofStr),
				hex.EncodeToString(p.rest_of_NTLM))
		}
	}
}

func makeSMBPacket(raw_packet gopacket.Packet) SMBPacket {
	var packet SMBPacket

	// Place the entire raw packet
	packet.payload = raw_packet.Data()
	// ApplicationLayer.Payload() includes the NetBIOS junk, which is generally unneeded
	packet.smbPacket = raw_packet.ApplicationLayer().Payload()[4:]
	packet.protocol_id = packet.smbPacket[:4]

	// Header length is directly after protocol id
	packet.header_length = bytesArrToInt(packet.smbPacket[4:5])
	packet.header = packet.smbPacket[:packet.header_length]

	packet.req_type = packet.header[12:14]

	// Require the "command" is "Session Setup Request"
	if bytes.Equal(packet.req_type, []byte{1, 0}) {
		// Length of "Structure Size" is the hex val at Structure size >> 1
		b := bytesArrToInt(packet.smbPacket[packet.header_length : packet.header_length+2])
		b = b >> 1
		blob_offset := bytesArrToInt(packet.smbPacket[packet.header_length+b : packet.header_length+b+2])

		/*
			Last bit in "Flags" determines if the packet is a request or a response
			Use binary and to determine if the last bit is set to 1 or not
		*/
		b = bytesArrToInt(packet.smbPacket[16:20])
		b = b & 1
		if b == 1 {
			packet.response = true
		} else {
			packet.response = false
		}

		if blob_offset < len(packet.smbPacket) {
			packet.blob = packet.smbPacket[blob_offset:]
			// Request packet
			if packet.response == false {
				if checkIdBytes(packet.smbPacket[blob_offset+16:], NTLMSSP_identifier) {
					packet.SSP = packet.blob[16:]
					if checkIdBytes(packet.SSP[8:], NTLMSSP_AUTH) {

						NTLM_Offset := bytesArrToInt(packet.SSP[24:28])
						NTLM_Maxlen := bytesArrToInt(packet.SSP[22:24])
						packet.NTLM_Response = packet.SSP[NTLM_Offset : NTLM_Offset+NTLM_Maxlen]
						packet.NTProofStr = packet.NTLM_Response[:16]
						packet.rest_of_NTLM = packet.NTLM_Response[16:]

						domain_Offset := bytesArrToInt(packet.SSP[32:36])
						domain_Maxlen := bytesArrToInt(packet.SSP[30:32])
						packet.domain = packet.SSP[domain_Offset : domain_Offset+domain_Maxlen]

						username_Offset := bytesArrToInt(packet.SSP[40:44])
						username_Maxlen := bytesArrToInt(packet.SSP[38:40])
						packet.username = packet.SSP[username_Offset : username_Offset+username_Maxlen]
					}
				}
				// Response packet
			} else {
				if len(packet.smbPacket) > blob_offset+33 && checkIdBytes(packet.smbPacket[blob_offset+33:], NTLMSSP_identifier) {
					packet.SSP = packet.blob[33:]
					if checkIdBytes(packet.SSP[8:], NTLMSSP_CHALLENGE) {
						packet.NT_challenge = packet.SSP[24:32]
					}
				}
			}
		}
	}
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
	parser := argparse.NewParser("go run main.go", "NTLM Extactor - Pull NetNTLMv2 hashes from a PCAP file")
	file := parser.String("f", "file", &argparse.Options{Required: true, Help: "Input PCAP file"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}
	// Call packet init sequence
	initPackets(*file)
	fmt.Println()
}
