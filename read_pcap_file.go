package main

import (
  "fmt"
  "log"
  "os"
  "strings"
  "strconv"
  "bytes"
  // "net"
  "path/filepath"
  // crc "hash/crc32"
  "encoding/hex"

  "github.com/sigurn/crc8"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
)

var (
  pcapFile string = "/home/mahabib/Downloads/wifi-traffic/wireshark_wlan0B2H2H1.pcapng"
  handle *pcap.Handle
  err error
  DEBUG bool = false
)

var IE_TAGS = [...]layers.Dot11InformationElementID {
  layers.Dot11InformationElementIDDSSet,
  layers.Dot11InformationElementIDExtCapability}

var IE_TAGS_IGNORE = [...]layers.Dot11InformationElementID {
  layers.Dot11InformationElementIDSSID}

func main() {
  // data := []byte{0x01, 0x02}
  // checkSum(data)
  // os.Exit(0)

  // pcap_file_ext := ".pcapng"
  pcap_file_ext := ".txt"
  // basePath := "/home/mahabib/Downloads/wifi-traffic"
  basePath := "/home/mahabib/data/wifi_traffic/rawfiles"
  // var b1 []string
  filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
    if err != nil {
      log.Fatal(err.Error())
    }
    if !strings.Contains(info.Name(), pcap_file_ext) {
      // fmt.Printf("Expected: %s, found: %s\n", pcap_file_ext, info.Name())
      return nil
    }
    // fmt.Printf("File name: %s\n", info.Name())

    // b1.WriteString(info.Name())
    // b1 = append(b1, info.Name())
    // read_source_mac(basePath+"/"+info.Name())
    test(basePath+"/"+info.Name())

    // os.Exit(0)
    return nil
  })
  // fmt.Println("Files: %s", strings.Join(b1, "\n"))
}

func read_source_mac(pcapFile string) (mac string, err error) {
  handle, err = pcap.OpenOffline(pcapFile)
  if err != nil {
    log.Fatal(err)
    return
  }
  defer handle.Close()

  fileName := pcapFile[strings.LastIndex(pcapFile, "/")+1:len(pcapFile)]

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  // fmt.Println("FILE: %s", pcapFile)
  for packet := range packetSource.Packets() {
    probeLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq)
    if probeLayer == nil {
      continue
    }

    dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
    macAddr := dot11.Address2
    macFixed := macAddr[0] & 0x02 == 0
    fmt.Printf("%s,%s,%s,%x,%s,%v\n", fileName, packet.Metadata().CaptureInfo.Timestamp, macAddr.String(), macAddr[0], strconv.FormatInt(int64(macAddr[0]), 2), !macFixed)
  }
  return "nil", nil
}


func checkSum(data []byte) byte {
  // h := crc.NewIEEE()
  // h.Write(data)
  // fmt.Println(h.Sum32())

  // chkSum := crc.ChecksumIEEE(data)
  // fmt.Println("Checksum: ", chkSum)

  crcTable := crc8.MakeTable(crc8.CRC8_MAXIM)
	crc := crc8.Checksum(data, crcTable)
	// fmt.Printf("CRC-8 MAXIM: %X\n", crc)
  return crc
}

func generateIEFootprint(ieFootprint *[6]byte, dot11ProbeReq *layers.Dot11MgmtProbeReq) (string, error) {
    if DEBUG {
        fmt.Println("\t", dot11ProbeReq.Contents)
    }
    // fmt.Println("\t", dot11ProbeReq.Contents)
    bin := dot11ProbeReq.Contents
    pkt := gopacket.NewPacket(bin, layers.LayerTypeDot11InformationElement, gopacket.NoCopy)
    if pkt.ErrorLayer() != nil {
		    // fmt.Errorf("Failed to decode packet:", pkt.ErrorLayer().Error())
        return "", pkt.ErrorLayer().Error()
	  }
    // var ieFootprint [6]byte
    var ieBuf bytes.Buffer

    // buf := gopacket.NewSerializeBuffer()
    i_fp_next := 0
    // var sLayers []gopacket.SerializableLayer
    for _, l := range pkt.Layers() {
      ie := l.(*layers.Dot11InformationElement)
      // sLayers = append(sLayers, ie)
      if DEBUG {
        fmt.Printf("%d, %d, %v, %v\n", ie.ID, ie.Length, ie.OUI, ie.Info)
        fmt.Println("\tIE: ", ie)
        fmt.Println("\tFP: ", ieFootprint)
      }

      tag_ignored := false
      for _, tag := range IE_TAGS_IGNORE {
        if ie.ID == tag {
          if DEBUG {
            log.Println("IE tag ignored: ", tag)
          }
          fmt.Fprintf(&ieBuf, "%d-%d:ignore,", ie.ID, ie.Length)
          tag_ignored = true
        }
      }

      if !tag_ignored {
        tag_val := ie.Info
        tag_id_taken := false
        for _, tag := range IE_TAGS {
          if ie.ID == tag {
            log.Printf("IE TAG:%d detected, ignore value", ie.ID)
            tag_val = []byte{byte(ie.ID)}
            tag_id_taken = true
          }
        }

        if tag_id_taken {
          fmt.Fprintf(&ieBuf, "%d-%d:%s#,", ie.ID, ie.Length, toHexString(ie.Info, "_"))
        } else {
            fmt.Fprintf(&ieBuf, "%d-%d:%s,", ie.ID, ie.Length, toHexString(ie.Info, "_"))
        }

        ieFootprint[i_fp_next] = 0xFF & (ieFootprint[i_fp_next] + checkSum(tag_val))
      }

      i_fp_next += 1
      i_fp_next = i_fp_next % len(ieFootprint)
    }
    // fmt.Println(ieBuf.String())

    // if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, sLayers...); err != nil {
    //   fmt.Errorf(err.Error())
    //   return nil, err
    // }
    // fmt.Println("Done")

    return ieBuf.String(), nil
}

func test(pcapFile string) {
  // open file instead of device
  // fmt.Println(pcapFile)
  pcapFilename := pcapFile[strings.LastIndex(pcapFile, "/")+1:]
  handle, err = pcap.OpenOffline(pcapFile)
  if err != nil {
    log.Fatal(err)
    return
  }
  defer handle.Close()

  //Loop through packets in file
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    ieFootprint := [6]byte {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    // fmt.Println(packet.Metadata().CaptureInfo.Timestamp)

    dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
    macAddr := dot11.Address2
    macFixed := macAddr[0] & 0x02 == 0

    dot11ProbeReq := packet.Layer(layers.LayerTypeDot11MgmtProbeReq).(*layers.Dot11MgmtProbeReq)
    if dot11ProbeReq != nil {
      ieStr, _ := generateIEFootprint(&ieFootprint, dot11ProbeReq)
      fmt.Printf("%s,%s,%s,%s,%s\n", pcapFilename, macAddr.String(), strconv.FormatBool(!macFixed), toHexString(ieFootprint[:], ":"), ieStr)
    }

    // for _, layer := range packet.Layers() {
    //   fmt.Println(layer.LayerType())
    //   // if layer.LayerType() == layers.LayerTypeDot11InformationElement {
    //   //   fmt.Println("Dot11-> ", layer)
    //   // }
    //   // if layer.LayerType() == layers.LayerTypeDot11MgmtProbeReq {
    //   //   handleDot11MgmtProbeReq(layer)
    //   // }
    // }
    // fmt.Println("\n")

    // break
  }
}

func toHexString(ba []byte, delim string) string {
  if len(ba) == 0 {return ""}
  var buffer bytes.Buffer
  for _, b := range ba {
      buffer.WriteString(hex.EncodeToString([]byte{b}))
      buffer.WriteString(delim)
  }
  str := buffer.String()
  return str[:len(str)-1]
}
