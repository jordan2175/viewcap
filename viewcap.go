// Copyright 2014-2015 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"code.google.com/p/getopt"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"strings"
)

var sOptPcapSrcFilename = getopt.StringLong("file", 'f', "", "Filename of the source PCAP file", "string")
var sOptMacAddress = getopt.StringLong("mac", 0, "", "The MAC Address to search for in AA:BB:CC:DD:EE:FF format", "string")
var sOptIPv4Address = getopt.StringLong("ip4", 0, "", "The IPv4 Address to change", "string")

var iOptHead = getopt.IntLong("head", 'h', 0, "Number of packets to show", "int")
var bOptHelp = getopt.BoolLong("help", 0, "Help")
var bOptVer = getopt.BoolLong("version", 0, "Version")

var iDebug = 0
var sVersion = "1.00"

//
//
//
// --------------------------------------------------------------------------------
// Function Main
// --------------------------------------------------------------------------------
func main() {
	getopt.HelpColumn = 26
	getopt.SetParameters("")
	getopt.Parse()
	checkCommandLineOptions()

	iHeadCount := *iOptHead

	// // Figure out if there is a change needed for the date of each packet.  We will
	// // compute the difference between what is in the first packet and what was passed
	// // in via the command line arguments.
	// pcapStartTimestamp := getFirstPacketTimestamp(*sOptPcapSrcFilename)

	// // Parse layer 2 addresses
	// userSuppliedMacAddress := parseSuppliedLayer2Address(*sOptMacAddress)

	// // Parse layer 3 IPv4 address
	// userSuppliedIPv4Address := parseSuppliedLayer3IPv4Address(*sOptIPv4Address)

	//
	// Get a handle to the PCAP source file so we can loop through each packet and make
	// changes as needed.
	handle, err1 := pcap.OpenOffline(*sOptPcapSrcFilename)
	if err1 != nil {
		fmt.Println(err1)
		os.Exit(0)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// -------------------------------------------------------------------------
	// Define counters for status
	// -------------------------------------------------------------------------
	iTotalPacketCounter := 0
	i802dot1QCounter := 0
	i802dot1QinQCounter := 0

	// -------------------------------------------------------------------------
	// Loop through every packet and update them as needed writing the changes
	// out to a new file
	// -------------------------------------------------------------------------
	for packet := range packetSource.Packets() {

		if *iOptHead != 0 && iHeadCount == 0 {
			return
		}

		ts := packet.Metadata().CaptureInfo.Timestamp
		dstMacAddressFromPacket := packet.LinkLayer().LayerContents()[0:6]
		srcMacAddressFromPacket := packet.LinkLayer().LayerContents()[6:12]

		sDstMacAddress := makePrettyMacAddress(dstMacAddressFromPacket)
		sSrcMacAddress := makePrettyMacAddress(srcMacAddressFromPacket)

		if *sOptMacAddress != "" {
			if sDstMacAddress != *sOptMacAddress && sSrcMacAddress != *sOptMacAddress {
				continue
			}
		}

		i802dot1QOffset := 0
		// ---------------------------------------------------------------------
		// Look for an 802.1Q frames
		// ---------------------------------------------------------------------
		if packet.LinkLayer().LayerContents()[12] == 81 && packet.LinkLayer().LayerContents()[13] == 0 {
			if iDebug == 1 {
				fmt.Println("DEBUG: Found an 802.1Q packet")
			}
			i802dot1QOffset = 4
			i802dot1QCounter++
		}

		// ---------------------------------------------------------------------
		// Look for an 802.1QinQ frame
		// ---------------------------------------------------------------------
		if packet.LinkLayer().LayerContents()[12] == 88 && packet.LinkLayer().LayerContents()[13] == 168 {
			if iDebug == 1 {
				fmt.Println("DEBUG: Found an 802.1QinQ packet")
			}
			i802dot1QOffset = 8
			i802dot1QinQCounter++
		}

		iEthType1 := 12 + i802dot1QOffset
		iEthType2 := 13 + i802dot1QOffset
		if packet.LinkLayer().LayerContents()[iEthType1] == 8 && packet.LinkLayer().LayerContents()[iEthType2] == 0 && packet.NetworkLayer().LayerContents()[0] == 69 {

			// Define the byte offsets for the data we are looking for
			iLayer3SrcIPStart := 12 + i802dot1QOffset
			iLayer3SrcIPEnd := iLayer3SrcIPStart + 4
			iLayer3DstIPStart := 16 + i802dot1QOffset
			iLayer3DstIPEnd := iLayer3DstIPStart + 4

			srcIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[iLayer3SrcIPStart:iLayer3SrcIPEnd]
			dstIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[iLayer3DstIPStart:iLayer3DstIPEnd]

			fmt.Print(ts, " - ", sSrcMacAddress)
			fmt.Printf(" - %-15s", makePrettyIPAddress(srcIPv4AddressFromPacket))
			fmt.Print(" > ", sDstMacAddress)
			fmt.Printf(" - %-15s\n", makePrettyIPAddress(dstIPv4AddressFromPacket))

		}

		// Write some output to the screen so users know we are doing something
		iTotalPacketCounter++

		if *iOptHead != 0 {
			iHeadCount--
		}

	} // End loop through every packet

	fmt.Println("\nTotal number of packets processed:", iTotalPacketCounter)
	fmt.Println("Total number of 802.1Q packets processed:", i802dot1QCounter)
	fmt.Println("Total number of 802.1QinQ packets processed:", i802dot1QinQCounter)
} // main()

//
// --------------------------------------------------------------------------------
// checkCommandLineOptions()
// --------------------------------------------------------------------------------
// Verify that all of the command line options meet the required dependencies
func checkCommandLineOptions() {
	if *bOptVer {
		fmt.Println("viewcap, copyright Bret Jordan, 2015")
		fmt.Println("Version:", sVersion)
		fmt.Println("")
		os.Exit(0)
	}

	if *bOptHelp || *sOptPcapSrcFilename == "" {
		fmt.Println("viewcap, copyright Bret Jordan, 2015")
		fmt.Println("Version:", sVersion)
		fmt.Println("")
		getopt.Usage()
		os.Exit(0)
	}

} //checkCommandLineOptions()

//
// -----------------------------------------------------------------------------
// areByteSlicesEqual
// -----------------------------------------------------------------------------
// Compare two byte slices to see if they are the same
func areByteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
} // areByteSlicesEqual

//
// -----------------------------------------------------------------------------
//  makePrettyMacAddress()
// -----------------------------------------------------------------------------
// This function will create a human readable MAC address in upper case using
// the : notation between octets
func makePrettyMacAddress(mac []byte) string {
	sMAC := strings.ToUpper(hex.EncodeToString(mac))
	var sNewMAC string

	// This will add a ":" after ever ODD index value but not on the last one
	for i, value := range sMAC {
		sNewMAC += string(value)
		if i%2 != 0 && i%11 != 0 {
			sNewMAC += ":"
		}
	}
	if iDebug == 1 {
		fmt.Println("DEBUG: MAC Address", sNewMAC)
	}

	return sNewMAC
} // makePrettyMacAddress()

//
// -----------------------------------------------------------------------------
//  makePrettyIPAddress()
// -----------------------------------------------------------------------------
// This function will create a human readable IP address
func makePrettyIPAddress(ip net.IP) string {
	return ip.String()
}
