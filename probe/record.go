package probe

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type ProbeRecord struct {
	Timestamp  int64
	Mac        string
	SequenceId int
	Rssi       int
	ApName     string
	// IEs
	
}

func init() {
	fmt.Println("record package initialized")
}

func (r *ProbeRecord) Values() (values url.Values) {
	values.Add("timestamp", strconv.FormatInt(r.Timestamp, 10))
	values.Add("mac", r.Mac)
	values.Add("sequence_id", strconv.Itoa(r.SequenceId))
	values.Add("rssi", strconv.Itoa(r.Rssi))
	// more fields
	return
}

func (r *ProbeRecord) String() string {
	ltime := time.Unix(r.Timestamp, 0).Local()
	return fmt.Sprintf("%s,%d,%s,%d,%d", ltime.Format(time.RFC3339), r.Timestamp, r.Mac, r.SequenceId, r.Rssi)
}
