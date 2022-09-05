// Note to future Josh from past Josh - when debugging, use hex.Dump([]byte)

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"github.com/common-nighthawk/go-figure"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Global vars for super cool colors
var colorGreen = "\033[32m"
var colorReset = "\033[0m"
var colorRed = "\033[31m"

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

// Colored print utils
func printSuccess(str string) {
	fmt.Printf("%s[*] %s%s\n", colorGreen, str, colorReset)
}
func printError(str string) {
	fmt.Printf("%s[*] %s%s\n", colorRed, colorReset, str)
}

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
	var packets []gopacket.Packet
	if file != "" {
		// Open PCAP from file
		if handle, err := pcap.OpenOffline(file); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				appLayer := packet.ApplicationLayer()
				// If there is an application layer in the packet and it isnt a little baby packet
				if appLayer != nil && len(appLayer.Payload()) > 10 {
					if checkIdBytes(appLayer.Payload()[4:8], smb_protocol_id) {
						packets = append(packets, packet)
					}
				}
			}
		}
		handleGoPackets(packets)
	}
}

func handleGoPackets(packets []gopacket.Packet) {
	var smbPackets []SMBPacket

	for _, p := range packets {
		smbPacket := makeSMBPacket(p)
		smbPackets = append(smbPackets, smbPacket)
	}

	extract_hashes(smbPackets)
}

// Format of hash
// [Username]::[Domain]:[NTLM Server Challenge]:[NTProofStr]:[Rest of NTLM Response]
func extract_hashes(packets []SMBPacket) {
	for i, p := range packets {
		if p.NTLM_Response != nil {
			printSuccess("Hash found")
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

func capturePackets(flag bool, device string) {
	if flag {
		if device == "" {
			findDevices()
		} else {
			packets := openDevice(device)
			handleGoPackets(packets)
		}
	}
}

func openDevice(device string) []gopacket.Packet {
	// Needed vars
	var (
		snapshot_len int32 = 1024
		promiscuous  bool  = false
		err          error
		timeout      time.Duration = 30 * time.Second
		handle       *pcap.Handle
		packets      []gopacket.Packet
		num_captured int
	)

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Capturing 100 SMB2 packets...")
	for packet := range packetSource.Packets() {
		appLayer := packet.ApplicationLayer()
		// If there is an application layer in the packet
		if appLayer != nil && len(appLayer.Payload()) > 10 {
			if checkIdBytes(appLayer.Payload()[4:8], smb_protocol_id) {
				packets = append(packets, packet)
				packets = append(packets, packet)
				num_captured++
			}
		}
		if num_captured > 100 {
			break
		}
	}
	return packets
}

func findDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Found devices")
	for _, dev := range devices {
		fmt.Println("\nName: ", dev.Name)
		fmt.Println("Description:", dev.Description)
		fmt.Println("Device addresses: ")
		for _, addr := range dev.Addresses {
			fmt.Printf("\tIP Address: %s\n", addr.IP)
			fmt.Printf("\tSubnet mask: %s\n", addr.Netmask)
		}
	}
}

func main() {
	// Print the banner
	fmt.Print(colorRed)
	banner := figure.NewFigure("NTLM Extract", "larry3d", true)
	banner.Print()
	fmt.Print(colorReset)

	// Set up the argparse system
	parser := argparse.NewParser("go run main.go", "NTLM Extactor - Carve NetNTLMv2 hashes from a your packets\n- Live capture SMB packets or supply a PCAP file to get started\n- Pls use for legal purposes only :)")
	file := parser.String("f", "file", &argparse.Options{Required: false, Help: "Input PCAP file"})
	live := parser.Flag("l", "live-capture", &argparse.Options{Required: false, Help: "Live capture of packets on your network"})
	device := parser.String("d", "device", &argparse.Options{Required: false, Help: "Device for live capture"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	fmt.Printf("%s\n\n", parser.GetDescription())

	capturePackets(*live, *device)
	// Call packet init sequence
	initPackets(*file)
	fmt.Println()
}
