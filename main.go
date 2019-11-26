package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
)

func main() {
	//get HECI Version
	var heciver HECIVersion
	var res = GetHECIVersion(&heciver)
	if res < 0 {
		log.Println("Main:GetHECIVersion: Failed to get HECI driver Version.")
	}
	log.Println("Main: HECI Version:", heciver)
	//get AMT UUID
	var amtuuid syscall.GUID
	res = GetAMTUUID(&amtuuid)
	if res < 0 {
		log.Println("Main:GetAMTUUID: Failed to get AMTUUID.")
	}
	//log.Printf("%x %x %x %x\n", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, amtuuid.Data4)
	amtuuidstr := fmt.Sprintf("%x-%x-%x-%s-%s", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, hex.EncodeToString(amtuuid.Data4[0:2]), hex.EncodeToString(amtuuid.Data4[2:]))
	log.Printf("Main: AMT UUID:%x-%x-%x-%s-%s", amtuuid.Data1, amtuuid.Data2, amtuuid.Data3, hex.EncodeToString(amtuuid.Data4[0:2]), hex.EncodeToString(amtuuid.Data4[2:]))

	//get local admin
	var amtcred LocalAdmin
	res = GetLocalAdmin(&amtcred)
	if res < 0 {
		log.Println("Main:GetLocalAdmin: Failed to get Local Admin credential")
	}
	log.Printf("Main: AMT Local Admin username: %s, password: %s", amtcred.Username, amtcred.Password)

	// APFClient to connect
	var apf = APFClient{}
	apf.apfuser = "z6Brkbi7IeIfvC0N"
	apf.apfpassword = "A@xew9rt"
	apf.apfurl = "wss://localhost/apf.ashx"
	apf.apfkeepalive = 60000
	apf.clientaddress = "127.0.0.1"
	apf.clientname = "corem5-compute-stick"
	apf.clientuuid = amtuuidstr
	apf.stopped = false
	// let's get it started
	StartAPFClient(&apf)
}
