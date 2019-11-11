// Copyright 2019 Intel Corporation. All rights reserved.
// Author: Joko Sastriawan
// License: APL 2.0

package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var addr = flag.String("addr", "localhost:443", "HTTPS service address")

// Various CIRA state
const (
	CiraStateInitial                int = 0
	CiraStateProtocolVersionSent        = 1
	CiraStateAuthServiceRequestSent     = 2
	CiraStateAuthRequestSent            = 3
	CiraStatePFWDServiceRequestSent     = 4
	CiraStateGlobalRequestSent          = 5
	CiraStateFailed                     = -1
)

// APF protocol message types
const (
	APFProtocolUnknown                 uint8 = 0
	APFProtocolDisconnect                    = 1
	APFProtocolServiceRequest                = 5
	APFProtocolServiceAccept                 = 6
	APFProtocolUserauthRequest               = 50
	APFProtocolUserauthFailure               = 51
	APFProtocolUserauthSuccess               = 52
	APFProtocolGlobalRequest                 = 80
	APFProtocolRequestSuccess                = 81
	APFProtocolRequestFailure                = 82
	APFProtocolChannelOpen                   = 90
	APFProtocolChannelOpenConfirmation       = 91
	APFProtocolChannelOpenFailure            = 92
	APFProtocolChannelWindowAdjust           = 93
	APFProtocolChannelData                   = 94
	APFProtocolChannelClose                  = 97
	APFProtocolProtocolVersion               = 192
	APFProtocolKeepaliveRequest              = 208
	APFProtocolKeepaliveReply                = 209
	APFProtocolKeepaliveOptionRequest        = 210
	APFProtocolKeepaliveOptionReply          = 211
)

var pfwdPorts = []int32{16992, 623, 16994, 5900}

// APFClient is to manage client data
type APFClient struct {
	apfurl        string
	apfuser       string
	apfpassword   string
	apfkeepalive  int
	clientname    string
	clientuuid    string
	clientaddress string
	stopped       bool
}

// DownlinkChannel keeps track individual channel inside APFConnection
type DownlinkChannel struct {
	channelType   string
	senderChannel int
	windowSize    int
	targetAddress string
	targetPort    int
	originAddress string
	originPort    int
	socket        net.Conn
}

// APFConnection keeps track the state of the APF connection to APFServer
type APFConnection struct {
	apfclient   *APFClient
	accumulator []byte
	conn        *websocket.Conn
	state       int
	PFwdIdx     int
	timer       chan bool
	channels    map[int]*DownlinkChannel
}

//StopAPFClient signals APFConnection for this APFCLient to stop
func StopAPFClient(apc *APFClient) {
	apc.stopped = true
}

// StartAPFClient starts APFClient
func StartAPFClient(apc *APFClient) {
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	log.Println("Url: ", apc.apfurl)
	u, _ := url.Parse(apc.apfurl)
	log.Printf("connecting to %s", u.String())

	dialer := websocket.Dialer{
		Subprotocols:    []string{"p1", "p2"},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	config := tls.Config{InsecureSkipVerify: true}
	dialer.TLSClientConfig = &config
	c, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial: ", resp.StatusCode, err)
	}

	// Fill up connection metadata
	apconn := APFConnection{}
	apconn.apfclient = apc
	apconn.conn = c

	defer c.Close()

	sig := make(chan os.Signal)
	signal.Notify(sig)

	msg := make(chan []byte)

	go func() {
		defer close(msg)
		//defer os.Exit(1)

		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("Read error message:", err)
				apconn.timer <- false
				apconn.apfclient.stopped = true
				return
			}
			//log.Println("Message len: ", len(message))
			if len(message) > 0 {
				msg <- message
			}
		}
	}()

	SendProtocolVersion(&apconn)
	SendServiceRequest(&apconn, "auth@amt.intel.com")

	//c.WriteMessage(1, []byte("Test"))
	for {
		select {
		case m := <-msg:
			//log.Printf("Receive message len: %d", len(m))
			if len(m) > 0 {
				apconn.accumulator = append(apconn.accumulator, m...)
				plen := ProcessData(&apconn)
				apconn.accumulator = apconn.accumulator[plen:]
			}
		case sg := <-sig:
			log.Printf("Received %s signal\n", sg)
			return
		}
		if apconn.apfclient.stopped {
			return
		}
	}
}

// SendProtocolVersion sends protocol version packet with UUID,
// this is the first packet to be sent by APF client to identify this package
func SendProtocolVersion(apfc *APFConnection) {
	//log.Println("UUID: ", apfc.apfclient.clientuuid)
	//log.Println("Stripped UUID: ", strings.Replace(apfc.apfclient.clientuuid, "-", "", -1))
	// reformat UUID into long long UUID
	uuid := strings.Replace(apfc.apfclient.clientuuid, "-", "", -1)
	intUUIDStr := uuid[6:8] + uuid[4:6] + uuid[2:4] + uuid[0:2] + uuid[10:12] + uuid[8:10] + uuid[14:16] + uuid[12:14] + uuid[16:20] + uuid[20:]
	//log.Println("Int UUID: ", intUUIDStr)
	uuidArr, err := hex.DecodeString(intUUIDStr)
	if err != nil {
		log.Fatal("Invalid UUID")
	}
	cmd := []byte{APFProtocolProtocolVersion, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
	blank := [64]byte{}
	cmd = append(cmd, uuidArr...)
	cmd = append(cmd, blank[0:]...)
	log.Printf("APF: SendProtocolVersion 1 0 %s", apfc.apfclient.clientuuid)
	apfc.conn.WriteMessage(2, cmd)
	apfc.state = CiraStateProtocolVersionSent
	//log.Println("Dump: ", hex.Dump(cmd))
}

// SendServiceRequest informs APF Server type of service to handle next request
func SendServiceRequest(apfc *APFConnection, service string) {
	slen := make([]byte, 4)
	binary.BigEndian.PutUint32(slen, uint32(len(service)))
	cmd := []byte{APFProtocolServiceRequest}
	cmd = append(cmd, slen[0:]...)
	cmd = append(cmd, service[0:]...)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send service request ", service)
	if service == "auth@amt.intel.com" {
		apfc.state = CiraStateAuthServiceRequestSent
	} else if service == "pfwd@amt.intel.com" {
		apfc.state = CiraStatePFWDServiceRequestSent
	}
}

// SendUserAuthRequest informs credentials to be verified by APF Server
func SendUserAuthRequest(apfc *APFConnection, user string, pass string) {
	svcname := "auth@amt.intel.com"
	cmd := []byte{APFProtocolUserauthRequest}
	slen := make([]byte, 4)
	binary.BigEndian.PutUint32(slen, uint32(len(svcname)))
	userlen := make([]byte, 4)
	binary.BigEndian.PutUint32(userlen, uint32(len(user)))
	passlen := make([]byte, 4)
	binary.BigEndian.PutUint32(passlen, uint32(len(pass)))
	cmd = append(cmd, userlen...)
	cmd = append(cmd, user...)
	cmd = append(cmd, slen...)
	cmd = append(cmd, svcname[0:]...)
	// add password
	cmd = append(cmd, 0, 0, 0, 8)
	cmd = append(cmd, []byte("password")...)
	cmd = append(cmd, 0)
	cmd = append(cmd, passlen...)
	cmd = append(cmd, pass[0:]...)
	apfc.conn.WriteMessage(2, cmd)
	apfc.state = CiraStateAuthRequestSent
	log.Printf("APF: Send user auth request for %s\n", user)
}

// SendGlobalRequestPfwd informs APF server the service port to forward to client
func SendGlobalRequestPfwd(apfc *APFConnection, amthostname string, amtport int32) {
	tcpipfwd := "tcpip-forward"
	cmd := []byte{APFProtocolGlobalRequest, 0, 0, 0, 13}
	cmd = append(cmd, tcpipfwd[0:]...)
	cmd = append(cmd, 1)
	hl := make([]byte, 4)
	binary.BigEndian.PutUint32(hl, uint32(len(amthostname)))
	cmd = append(cmd, hl...)
	cmd = append(cmd, amthostname...)
	pstr := make([]byte, 4)
	binary.BigEndian.PutUint32(pstr, uint32(amtport))
	cmd = append(cmd, pstr...)
	apfc.conn.WriteMessage(2, cmd)
	log.Printf("APF: Send tcpip-forward %s:%d\n", amthostname, amtport)
	apfc.state = CiraStateGlobalRequestSent
}

// SendKeepAliveRequest sends cookie to APF to query if APF server is still alive
func SendKeepAliveRequest(apfc *APFConnection) {
	cmd := []byte{APFProtocolKeepaliveRequest, 0, 0, 0, 255}
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send keepalive request")
}

// SendKeepAliveReply replies APF keepalive request with cookie to signify that client is still alive
func SendKeepAliveReply(apfc *APFConnection, cookie uint32) {
	cmd := []byte{APFProtocolKeepaliveReply}
	ck := make([]byte, 4)
	binary.BigEndian.PutUint32(ck, cookie)
	cmd = append(cmd, ck...)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send keepalive reply")
}

// setInterval emulation: https://www.loxodrome.io/post/set-timeout-interval-go/
func setInterval(someFunc func(), milliseconds int, async bool) chan bool {

	interval := time.Duration(milliseconds) * time.Millisecond

	ticker := time.NewTicker(interval)
	clear := make(chan bool)

	go func() {
		for {
			select {
			case <-ticker.C:
				if async {
					// This won't block
					go someFunc()
				} else {
					// This will block
					someFunc()
				}
			case <-clear:
				ticker.Stop()
				return
			}

		}
	}()
	return clear
}

// ParseChannelOpen fills up Downlink information required to track every channel about to be established
func ParseChannelOpen(data []byte, dl *DownlinkChannel) int {
	ctlen := int(binary.BigEndian.Uint32(data[1:5]))
	dl.channelType = string(data[5 : 5+ctlen])
	dl.senderChannel = int(binary.BigEndian.Uint32(data[5+ctlen : 9+ctlen]))
	dl.windowSize = int(binary.BigEndian.Uint32(data[9+ctlen : 13+ctlen]))
	tlen := int(binary.BigEndian.Uint32(data[17+ctlen : 21+ctlen]))
	dl.targetAddress = string(data[21+ctlen : 21+ctlen+tlen])
	dl.targetPort = int(binary.BigEndian.Uint32(data[21+ctlen+tlen : 25+ctlen+tlen]))
	olen := int(binary.BigEndian.Uint32(data[25+ctlen+tlen : 29+ctlen+tlen]))
	dl.originAddress = string(data[29+ctlen+tlen : 29+ctlen+tlen+olen])
	dl.originPort = int(binary.BigEndian.Uint32(data[29+ctlen+tlen+olen : 33+ctlen+tlen+olen]))
	return 33 + ctlen + tlen + olen
}

// SendChannelOpenFailure informs APF Server that channel open request cannot be fulfilled
func SendChannelOpenFailure(apfc *APFConnection, chandata *DownlinkChannel) {
	cmd := []byte{APFProtocolChannelOpenFailure}
	sendercan := make([]byte, 4)
	binary.BigEndian.PutUint32(sendercan, uint32(chandata.senderChannel))
	cmd = append(cmd, sendercan...)
	cmd = append(cmd, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send ChannelOpenFailure")
}

// SendChannelOpenConfirm informs APF Server that channel open request success
func SendChannelOpenConfirm(apfc *APFConnection, chandata *DownlinkChannel) {
	cmd := []byte{APFProtocolChannelOpenConfirmation}
	senderchan := make([]byte, 4)
	binary.BigEndian.PutUint32(senderchan, uint32(chandata.senderChannel))
	cmd = append(cmd, senderchan...)
	// just use the same receiver channel
	cmd = append(cmd, senderchan...)
	// send back window size as initial windows size
	wsize := make([]byte, 4)
	binary.BigEndian.PutUint32(wsize, uint32(chandata.windowSize))
	cmd = append(cmd, wsize...)
	cmd = append(cmd, 255, 255, 255, 255)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send ChannelOpenConfirm")
}

// SendChannelWindowAdjust informs APF Server how many bytes buffer has become available
func SendChannelWindowAdjust(apfc *APFConnection, chanNum int, size int) {
	cmd := []byte{APFProtocolChannelWindowAdjust}
	chanbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(chanbyte, uint32(chanNum))
	cmd = append(cmd, chanbyte...)
	adjSize := make([]byte, 4)
	binary.BigEndian.PutUint32(adjSize, uint32(chanNum))
	cmd = append(cmd, adjSize...)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send ChannelWindowAdjust")
}

// SendChannelData wraps and sends data to specific channel
func SendChannelData(apfc *APFConnection, chanNum int, len int, data []byte) {
	cmd := []byte{APFProtocolChannelData}
	chanbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(chanbyte, uint32(chanNum))
	cmd = append(cmd, chanbyte...)
	dlen := make([]byte, 4)
	binary.BigEndian.PutUint32(dlen, uint32(len))
	cmd = append(cmd, dlen...)
	cmd = append(cmd, data...)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send ChannelData ")
}

// SendChannelClose informs APF Server intent to close an established channel
func SendChannelClose(apfc *APFConnection, chanNum int) {
	cmd := []byte{APFProtocolChannelClose}
	chanbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(chanbyte, uint32(chanNum))
	cmd = append(cmd, chanbyte...)
	apfc.conn.WriteMessage(2, cmd)
	log.Println("APF: Send ChannelClose:", chanNum)
}

// AllowPortForward checks if port is allowed to forward
func AllowPortForward(pnum int) bool {
	for _, item := range pfwdPorts {
		if item == int32(pnum) {
			return true
		}
	}
	return false
}

// ProcessData consumes buffers of received bytestream from APF server
func ProcessData(apfc *APFConnection) int {
	plen := 0
	inplen := len(apfc.accumulator)
	switch cmd := apfc.accumulator[0]; cmd {
	case APFProtocolServiceAccept:
		svclen := binary.BigEndian.Uint32(apfc.accumulator[1:5])
		if inplen >= int(svclen)-5 {
			svcname := string(apfc.accumulator[5 : 5+svclen])
			log.Printf("APF: Receive APFProtocolService accept: %s.\n", svcname)
			if svcname == "auth@amt.intel.com" {
				if apfc.state >= CiraStateAuthServiceRequestSent {
					SendUserAuthRequest(apfc, apfc.apfclient.apfuser, apfc.apfclient.apfpassword)
				}
			} else if svcname == "pfwd@amt.intel.com" {
				if apfc.state >= CiraStatePFWDServiceRequestSent {
					SendGlobalRequestPfwd(apfc, apfc.apfclient.clientname, pfwdPorts[apfc.PFwdIdx])
					apfc.PFwdIdx++
				}
			}
			plen = 5 + int(svclen)
		}
	case APFProtocolRequestSuccess:
		if inplen >= 5 {
			fwdPort := binary.BigEndian.Uint32(apfc.accumulator[1:5])
			log.Println("APF: Request to port forward", fwdPort, "successful.")
			// iterate to pending port forward request
			if apfc.PFwdIdx < len(pfwdPorts) {
				SendGlobalRequestPfwd(apfc, apfc.apfclient.clientname, pfwdPorts[apfc.PFwdIdx])
				apfc.PFwdIdx++
				plen = 1
			} else {
				// instantiate the channels tracking
				apfc.channels = make(map[int]*DownlinkChannel)
				// no more port forward, now setup timer to send keep alive
				log.Printf("APF: Start keep alive for every %d ms.\n", apfc.apfclient.apfkeepalive)
				apfc.timer = setInterval(func() {
					SendKeepAliveRequest(apfc)
				}, apfc.apfclient.apfkeepalive, true)
			}
			plen = 5
		}
	case APFProtocolUserauthSuccess:
		log.Println("APF: User Authentication successful")
		// Send Pfwd service request
		SendServiceRequest(apfc, "pfwd@amt.intel.com")
		plen = 1
	case APFProtocolUserauthFailure:
		log.Println("APF: User Authentication failure")
		apfc.state = CiraStateFailed
		plen = 14
	case APFProtocolKeepaliveRequest:
		log.Printf("APF: Keep Alive Request with cookie: %d\n", binary.BigEndian.Uint32(apfc.accumulator[1:5]))
		SendKeepAliveReply(apfc, binary.BigEndian.Uint32(apfc.accumulator[1:5]))
		plen = 5
	case APFProtocolKeepaliveReply:
		log.Printf("APF: Keep Alive Reply with cookie: %d\n", binary.BigEndian.Uint32(apfc.accumulator[1:5]))
		plen = 5
	case APFProtocolChannelOpen:
		log.Println("APF: Channel Open request received")
		dl := DownlinkChannel{}
		plen = ParseChannelOpen(apfc.accumulator, &dl)
		// let's check if dl.targetPort is allowed to forward, check pfwdPorts containes it
		if AllowPortForward(dl.targetPort) {
			addr := fmt.Sprintf("%s:%d", apfc.apfclient.clientaddress, dl.targetPort)
			con, err := net.Dial("tcp", addr)
			if err != nil {
				SendChannelOpenFailure(apfc, &dl)
			} else {
				dl.socket = con
				apfc.channels[dl.senderChannel] = &dl
				go func(cn *APFConnection, d *DownlinkChannel) {
					tcon := d.socket
					// defer socket connection close
					defer d.socket.Close()
					buf := make([]byte, 4096)
					for {
						tcon.SetReadDeadline(time.Now().Add(time.Second))
						cnt, err := tcon.Read(buf)
						if err != nil {
							// Close and remove from active channel list if closed
							if err == io.EOF {
								log.Println("APF: Downlink connection is closed.")
								SendChannelClose(cn, d.senderChannel)
								delete(cn.channels, d.senderChannel)
								return
							}
						}
						if cnt > 0 {
							log.Println("APF: Received data from downlink ", cnt, " bytes.")
							SendChannelData(cn, d.senderChannel, cnt, buf[0:cnt])
						}
					}
				}(apfc, &dl)

				// Inform APF Server that port is open now
				SendChannelOpenConfirm(apfc, &dl)
			}
		} else {
			SendChannelOpenFailure(apfc, &dl)
		}
	case APFProtocolChannelOpenConfirmation:
		plen = 17
	case APFProtocolChannelClose:
		rchan := int(binary.BigEndian.Uint32(apfc.accumulator[1:5]))
		log.Println("APF: Received channel close", rchan)
		if apfc.channels[rchan] != nil {
			SendChannelClose(apfc, rchan)
			// Try closing it if exist
			_, ok := apfc.channels[rchan]
			if ok {
				apfc.channels[rchan].socket.Close()
			}
			delete(apfc.channels, rchan)
		}
	case APFProtocolChannelData:
		rchan := int(binary.BigEndian.Uint32(apfc.accumulator[1:5]))
		log.Println("APF: Received channel data", rchan)
		dlen := int(binary.BigEndian.Uint32(apfc.accumulator[5:9]))
		el, ok := apfc.channels[rchan]
		// send if found otherwise send channel close
		if ok {
			el.socket.Write(apfc.accumulator[9 : 9+dlen])
			SendChannelWindowAdjust(apfc, rchan, dlen)
		} else {
			SendChannelClose(apfc, rchan)
		}
		plen = 9 + dlen
	case APFProtocolChannelWindowAdjust:
		plen = 9
	default:
		log.Printf("Unknown APF command: %d\n", cmd)
		apfc.state = CiraStateFailed
		apfc.conn.Close()
		plen = 0
	}

	return plen
}
