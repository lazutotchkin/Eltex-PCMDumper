// v24.10.19
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

var colorReset = "\033[0m"

var colorRed = "\033[31m"
var colorYellow = "\033[33m"
var colorBlue = "\033[34m"

var colorRedBackground = "\033[41m"
var colorWhite = "\033[97m"

/*
func toHexString(byte []array) String {
	return DatatypeConverter.printHexBinary(array).toUpperCase()
}
*/
/*
func asBits(val uint64) []uint64 {
	bits := []uint64{}
	for i := 0; i < 24; i++ {
		bits = append([]uint64{val & 0x1}, bits...)
		// or
		// bits = append(bits, val & 0x1)
		// depending on the order you want
		val = val >> 1
	}
	return bits
}
*/

func hexToBin(hex string) string {
	//var hex string
	hex = strings.ReplaceAll(hex, "0", "0000")
	hex = strings.ReplaceAll(hex, "1", "0001")
	hex = strings.ReplaceAll(hex, "2", "0010")
	hex = strings.ReplaceAll(hex, "3", "0011")
	hex = strings.ReplaceAll(hex, "4", "0100")
	hex = strings.ReplaceAll(hex, "5", "0101")
	hex = strings.ReplaceAll(hex, "6", "0110")
	hex = strings.ReplaceAll(hex, "7", "0111")
	hex = strings.ReplaceAll(hex, "8", "1000")
	hex = strings.ReplaceAll(hex, "9", "1001")
	hex = strings.ReplaceAll(hex, "a", "1010")
	hex = strings.ReplaceAll(hex, "b", "1011")
	hex = strings.ReplaceAll(hex, "c", "1100")
	hex = strings.ReplaceAll(hex, "d", "1101")
	hex = strings.ReplaceAll(hex, "e", "1110")
	hex = strings.ReplaceAll(hex, "f", "1111")

	return hex
}

func sendToSniffer(Request []byte) {
	//Request := []byte{0xff, 0xff, 0xff, 0xff, 0x69, 0x6e, 0x66, 0x6f, 0x20, 0x34, 0x39}
	conn, err := net.Dial("udp", "127.0.0.1:9777")
	if err != nil {
		println("UDP Error on sending to sniffer")
		return
	}
	// send to server
	fmt.Fprintf(conn, string(Request))
}

func getMSGTname(typeInt int) string {
	switch typeInt {
	case 1:
		return "IAM"
	case 2:
		return "SAM"
	case 3:
		return "INR"
	case 4:
		return "INF"
	case 5:
		return "COT"
	case 6:
		return "ACM"
	case 7:
		return "CON"
	case 8:
		return "FOT"
	case 9:
		return "ANM"
	case 12:
		return "REL"
	case 13:
		return "SUS"
	case 14:
		return "RES"
	case 16:
		return "RLC"
	case 17:
		return "CCR"
	case 44:
		return "CPG"
	default:
		return strconv.Itoa(typeInt)
	}
}

func main() {

	addr := net.UDPAddr{
		Port: 9888,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	fmt.Println("Bind on", addr.String())

	buf := make([]byte, 256)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		buf := buf[16:n]
		sendToSniffer(buf)

		println(colorRedBackground + colorWhite + addr.String() + colorReset + " lenB=" + strconv.Itoa(n) + "-16=" + strconv.Itoa(n-16))
		//println(string(buf[:n]))
		//println(hex.DecodeString(string(buf[:n])))
		println(colorYellow + hex.Dump((buf[:n])) + colorReset)
		//packetHex := hex.EncodeToString((buf[:n]))
		//packetBin := hexToBin(hex.EncodeToString((buf[:n])))
		//println(packetHex + " (" + packetBin + " ) lenb=" + strconv.Itoa(len(packetBin)) + colorReset)

		MTP2 := hex.EncodeToString((buf[:3]))
		println("MTP2: " + MTP2 + " ( " + hexToBin(MTP2) + " ) lenb=" + strconv.Itoa(len(hexToBin(MTP2))) + colorReset)

		//println(colorRed)
		//for i, h := range buf[:3] {
		//	if i < 3 {
		//		fmt.Printf("%08b ", h) // prints 00000000 11111101
		//		//println(i)
		//	}
		//}
		//println(colorReset + "")

		MTP3hex := hex.EncodeToString((buf[3:8]))
		MTP3bin := hexToBin(MTP3hex)
		println("MTP3: " + MTP3hex + " ( " + MTP3bin + " ) lenb=" + strconv.Itoa(len(MTP3bin)) + colorReset)

		//println(colorRed)
		//for i, h := range buf[3:8] {
		//	if i < 5 {
		//		fmt.Printf("%08b ", h) // prints 00000000 11111101
		//println(i)
		//	}
		//}
		//println(colorReset + "")

		//for x := 0; x < n; x++ {
		//	fmt.Printf("%08b ", n2) // prints 00000000 11111101
		//}

		//NI: 11.. ....
		print("    NI: ")
		switch MTP3bin[:2] {
		case "00":
			print("International (0)")
		case "01":
			print("Reserved for international use (1)")
		case "10":
			print("National network (2)")
		case "11":
			print("Reserved for national use (3)")

		}
		println("")

		//if strings.Index(MTP3bin, "11") == 0 {
		//	println("    NI: Reserv of national network")
		//}

		//Skip Spare ..00 ....

		//SIO: .... 0101
		if strings.Index(MTP3bin[4:], "0101") == 0 {
			println("    SIO: ISUP")
		}

		//Routing label is 4 byte in reverse order
		//println(colorBlue)
		MTP3RLbin := ""
		for i, h := range slices.Backward(buf[4:8]) {
			if i < 4 {
				//fmt.Printf("%08b ", h) // prints 00000000 11111101
				MTP3RLbin = MTP3RLbin + fmt.Sprintf("%08b", h)
				//println(i)
			}
		}
		//println(MTP3RLbin)
		//println(colorReset + "")

		//SLC 1111 .... .... .... .... .... .... ....
		SLC := MTP3RLbin[:4]
		SLCdec, _ := strconv.ParseInt(SLC, 2, 16)
		println("    SLC: " + strconv.Itoa(int(SLCdec)) + " (" + SLC + ")")

		//OPC .... 0000 0000 0000 01.. .... .... ....
		OPC := MTP3RLbin[4:18]
		OPCdec, _ := strconv.ParseInt(OPC, 2, 16)
		println("    OPC: " + strconv.Itoa(int(OPCdec)) + " (" + OPC + ")")

		//DPC .... .... .... .... ..00 0000 0000 0001
		DPC := MTP3RLbin[18:32]
		DPCdec, _ := strconv.ParseInt(DPC, 2, 16)
		println("    DPC: " + strconv.Itoa(int(DPCdec)) + " (" + DPC + ")")

		println("")
		println("ISUP: ")
		ISUPBin := hexToBin(hex.EncodeToString((buf[8:n])))
		//println(ISUPBin)

		//CIC is first byte of ISUP
		CIC := ISUPBin[:8]
		CICdec, _ := strconv.ParseInt(CIC, 2, 16)
		println("    CIC: " + strconv.Itoa(int(CICdec)) + " (" + CIC + ")")

		//Message Type is 3rd byte of ISUP
		MSGT := ISUPBin[16:24]
		MSGTdec, _ := strconv.ParseInt(MSGT, 2, 16)
		println("    MSGT: " + getMSGTname(int(MSGTdec)) + " (" + MSGT + ")")

		if getMSGTname(int(MSGTdec)) == "IAM" {

		}

		println("")

		/*
			println(colorWhite)
			for i, h := range buf {
				if i < n {
					fmt.Printf("%08b ", h) // prints 00000000 11111101
					//println(i)
				}
			}
			println(colorReset + "")
		*/

		//os.Exit(0)
	}

}
