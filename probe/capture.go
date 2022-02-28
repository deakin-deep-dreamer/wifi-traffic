package probe

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ProbeSource struct {
	c    chan ProbeRecord
	stop chan bool
}

func init() {
	fmt.Println("capture package initialized")
}

func (s *ProbeSource) Records() chan ProbeRecord {
	return s.c
}

func (s *ProbeSource) Close() {
	s.stop <- true
}

func NewProbeSource(device string) (*ProbeSource, error) {
	var handle *pcap.Handle
	var err error
	if device == "" {
		return nil, error.New("No device specified.")
	}
	handle, err = openAsMonitorMode(device)
	if err != nil {
		return nil, err
	}
	log.Printf("pacp version: %s\n", pcap.Version())

	source := &ProbeSource{
		c:    make(chan ProbeRecord),
		stop: make(chan bool),
	}

	go func() {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case packet := <-packetSource.Packets():
				// decode and find ProbeRequest
				probeLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq)
				if probeLayer == nil {
					continue
				}

				dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
				radioTap := packet.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap)

				source.c <- ProbeRecord{
					Timestamp:  packet.Metadata().Timestamp.Unix(),
					Mac:        dot11.Address2.String(),
					Rssi:       int(radioTap.DBMAntennaSignal),
					SequenceId: int(dot11.SequenceNumber),
				}
			case <-source.stop:
				break
			}
		}
	}()

	return source, nil
}

func openAsMonitorMode(device string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, fmt.Errorf("NewInactiveHandle(%s) failed: %s", device, err)
	}
	defer inactive.Cleanup()

	// change mode to monitor
	if err := inactive.SetRFMon(true); err != nil {
		return nil, fmt.Errorf("SetRFMon failed: %s", err)
	}

	// create the actual handle by calling Activate
	handle, err := inactive.Activate() // after this, inactive is no longer valid
	if handle == nil {
		return nil, fmt.Errorf("Activate(%s) failed: %s", device, err)
	}
	return handle, nil
}
