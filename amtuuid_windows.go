// +build windows,amd64

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

//HeciGUID is Windows device identifier for HECI device
var HeciGUID = syscall.GUID{
	Data1: 0xE2D1FF34,
	Data2: 0x3458,
	Data3: 0x49A9,
	Data4: [8]byte{0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5},
}

// AMTHIGUID is host interface in HECI for AMT communication
var AMTHIGUID = syscall.GUID{
	Data1: 0x12F80028,
	Data2: 0xb4b7,
	Data3: 0x4b2d,
	Data4: [8]byte{0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c},
}

//FWClient track the protocol version and max message length
type FWClient struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
}

//AMTVersion contains information about AMT version
type AMTVersion struct {
	Major  uint8
	Minor  uint8
	Hotfix uint8
	Build  uint16
}

//HECIVersion contains information about HECI driver version
type HECIVersion struct {
	Major  uint8
	Minor  uint8
	Hotfix uint8
	Build  uint16
}

//AMTHIMessageHeader contains AMTHI command message
type AMTHIMessageHeader struct {
	Major    uint8
	Minor    uint8
	Reserved uint16
	Command  uint32
	Length   uint32
}

//LocalAdmin stores AMT local credential for activation purpose
type LocalAdmin struct {
	Username string
	Password string
}

//GetDevicePath should return the resource path of HECI interface
func GetDevicePath() []uint16 {
	var ret []uint16
	var modcfgmgr = syscall.NewLazyDLL("cfgmgr32.dll")
	var getDevIntfListSize = modcfgmgr.NewProc("CM_Get_Device_Interface_List_SizeW")
	var getDevintfList = modcfgmgr.NewProc("CM_Get_Device_Interface_ListW")

	var devCount = 0
	res, _, err := getDevIntfListSize.Call(
		uintptr(unsafe.Pointer(&devCount)),
		uintptr(unsafe.Pointer(&HeciGUID)),
		uintptr(uint32(0)),
		uintptr(uint32(0)))
	if res != 0 {
		log.Println("GetDevicePath:", err)
		return ret
	}
	var path []uint16 = make([]uint16, devCount)
	var pathptr *uint16 = &path[0]
	res, _, err = getDevintfList.Call(
		uintptr(unsafe.Pointer(&HeciGUID)),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(pathptr)),
		uintptr(devCount),
		uintptr(uint32(0)))

	if res != 0 {
		log.Println("GetDevicePath:", err)
		return ret
	}
	ret = path
	return ret
}

// ConnectAMTHI attempts to connect to AMTHI HECI path and query protocol versin and max message length
func ConnectAMTHI(h windows.Handle, fwc *FWClient) int32 {
	if h == windows.InvalidHandle || fwc == nil {
		return -1
	}
	var iocode uint32 = (0x8000 << 16) | (0x3 << 14) | (0x801 << 2) | 0
	var bp = (*byte)(unsafe.Pointer(&AMTHIGUID))
	var outbp = (*byte)(unsafe.Pointer(fwc))
	var byteret uint32 = 0
	var err = windows.DeviceIoControl(h, iocode, bp, 16, outbp, 5, &byteret, nil)
	if windows.GetLastError() != nil {
		log.Println("ConnectAMTHI:DeviceIoControl:", err, windows.GetLastError())
	}
	log.Println("ConnectAMTHI:FWClient: ", fwc)
	if byteret > 0 {
		return 1
	}
	return -1
}

//GetHECIVersion retrieves HECI driver version from HECI AMT HIF
func GetHECIVersion(h windows.Handle, amtver *HECIVersion) int32 {
	if h == windows.InvalidHandle || amtver == nil {
		return -1
	}
	var iocode uint32 = (0x8000 << 16) | (0x3 << 14) | (0x800 << 2) | 0
	var outbp = (*byte)(unsafe.Pointer(amtver))
	var byteret uint32 = 0
	var err = windows.DeviceIoControl(h, iocode, nil, 16, outbp, 5, &byteret, nil)
	if windows.GetLastError() != nil {
		log.Println("GetHECIVersion:DeviceIoControl:", err, windows.GetLastError())
	}
	log.Println("GetHECIVersion:AMT Version: ", amtver)
	if byteret > 0 {
		return 1
	}
	return -1
}

//GetAMTUUID retrieves AMT UUID via AMTHIF HECI
func GetAMTUUID(h windows.Handle, amtuuid *syscall.GUID) int32 {
	if h == windows.InvalidHandle || amtuuid == nil {
		return -1
	}
	var cmd = AMTHIMessageHeader{}
	cmd.Major = 1
	cmd.Minor = 1
	cmd.Command = 0x0400005C
	var done uint32 = 0
	var outbuf = []byte{0x1, 0x1, 0x0, 0x0}
	var cmdcommand = make([]byte, 4)
	binary.LittleEndian.PutUint32(cmdcommand, cmd.Command)
	outbuf = append(outbuf, cmdcommand...)
	var cmdlength = []byte{0x0, 0x0, 0x0, 0x0}
	outbuf = append(outbuf, cmdlength...)
	//log.Println("Writing: ", len(outbuf), hex.EncodeToString(outbuf[0:12]))
	var err = windows.WriteFile(h, outbuf[0:12], &done, nil)
	if windows.GetLastError() != nil {
		log.Println("GetAMTUUID:WriteFile:", done, err)
		return -1
	}
	log.Println("GetAMTUUID:WriteFile:done:", done)
	done = 0
	var buf = make([]byte, 5120)
	err = windows.ReadFile(h, buf, &done, nil)
	if windows.GetLastError() != nil {
		log.Println("GetAMTUUID:ReadFile:", done, err)
		return -1
	}
	log.Println("GetAMTUUID:ReadFile:done:", done)
	log.Println("GetAMTUUID:", hex.EncodeToString(buf[16:32]))
	if done > 0 {
		amtuuid.Data1 = binary.LittleEndian.Uint32(buf[16:20])
		amtuuid.Data2 = binary.LittleEndian.Uint16(buf[20:22])
		amtuuid.Data3 = binary.LittleEndian.Uint16(buf[22:24])
		copy(amtuuid.Data4[0:], buf[24:32])
		return 1
	}
	return -1
}

//GetLocalAdmin retrieves AMT $OsAdmin credential
func GetLocalAdmin(h windows.Handle, cred *LocalAdmin) int32 {
	if h == windows.InvalidHandle || cred == nil {
		return -1
	}
	var cmd = AMTHIMessageHeader{}
	cmd.Major = 1
	cmd.Minor = 1
	cmd.Command = 0x04000067
	var done uint32 = 0
	var outbuf = []byte{0x1, 0x1, 0x0, 0x0}
	var cmdcommand = make([]byte, 4)
	binary.LittleEndian.PutUint32(cmdcommand, cmd.Command)
	outbuf = append(outbuf, cmdcommand...)
	var cmdlength = []byte{0x0, 0x0, 0x0, 0x0}
	binary.LittleEndian.PutUint32(cmdlength, 40)
	outbuf = append(outbuf, cmdlength...)
	var trail = make([]byte, 40)
	outbuf = append(outbuf, trail...)
	//log.Println("Writing: ", len(outbuf), hex.EncodeToString(outbuf[0:]))
	var err = windows.WriteFile(h, outbuf[0:], &done, nil)
	if windows.GetLastError() != nil {
		log.Println("GetLocalAdmin:WriteFile:", done, err)
		return -1
	}
	log.Println("GetLocalAdmin:WriteFile:done:", done)
	done = 0
	var buf = make([]byte, 5120)
	err = windows.ReadFile(h, buf, &done, nil)
	if windows.GetLastError() != nil {
		log.Println("GetLocalAdmin:ReadFile:", done, err)
		return -1
	}
	log.Println("GetLocalAdmin:ReadFile:done:", done)
	log.Println("GetLocalAdmin:", hex.EncodeToString(buf[16:done]))
	if done > 20 {
		var rawcred = buf[16:done]
		cred.Username = string(bytes.Trim(rawcred[0:33], "\x00"))
		cred.Password = string(bytes.Trim(rawcred[33:], "\x00"))
		return 1
	}
	return -1
}

//var apc = APFClient{
//	"wss://localhost:443/apf.ashx",
//	"KfoAcdiaycDcnog4",
//	"P@ssw0rd",
//	60000,
//	"test-machine",
//	"8dad96cb-c3db-11e6-9c43-bc0000d20000",
//	"10.2.55.131",
//}

func main() {
	var p = GetDevicePath()
	log.Printf("GetDevicePath: %s\n", string(utf16.Decode(p)))
	var handle, err = windows.CreateFile(&p[0], windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		log.Println("Main:CreateFile:", err)
		return
	}
	// connect to AMTHI
	var fwc FWClient
	var res = ConnectAMTHI(handle, &fwc)
	if res < 0 {
		log.Println("Main:ConnectAMTHI: Failed to connect to AMTHI.")
	}
	log.Println("Main: FW Client:", fwc)
	//get HECI Version
	var heciver HECIVersion
	res = GetHECIVersion(handle, &heciver)
	if res < 0 {
		log.Println("Main:GetHECIVersion: Failed to get HECI driver Version.")
	}
	log.Println("Main: HECI Version:", heciver)
	//get AMT UUID
	var amtuuid syscall.GUID
	res = GetAMTUUID(handle, &amtuuid)
	if res < 0 {
		log.Println("Main:GetAMTUUID: Failed to get AMTUUID.")
	}
	//log.Printf("%x %x %x %x\n", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, amtuuid.Data4)
	amtuuidstr := fmt.Sprintf("%x-%x-%x-%s-%s", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, hex.EncodeToString(amtuuid.Data4[0:2]), hex.EncodeToString(amtuuid.Data4[2:]))
	log.Printf("Main: AMT UUID:%x-%x-%x-%s-%s", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, hex.EncodeToString(amtuuid.Data4[0:2]), hex.EncodeToString(amtuuid.Data4[2:]))

	//get local admin
	var amtcred LocalAdmin
	res = GetLocalAdmin(handle, &amtcred)
	if res < 0 {
		log.Println("Main:GetLocalAdmin: Failed to get Local Admin credential")
	}
	log.Printf("Main: AMT Local Admin username: %s, password: %s", amtcred.Username, amtcred.Password)
	windows.CloseHandle(handle)
	// APFClient to connect
	var apf = APFClient{}
	apf.apfuser = "9e15bf4f5766d45c"
	apf.apfpassword = "A@xew9rt"
	apf.apfurl = "wss://meshcentral.com/apf.ashx"
	apf.apfkeepalive = 60000
	apf.clientaddress = "127.0.0.1"
	apf.clientname = "corem5-compute-stick"
	apf.clientuuid = amtuuidstr
	apf.stopped = false
	// let's get it started
	StartAPFClient(&apf)
}
