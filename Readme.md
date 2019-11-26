# Provisioning agent using APF Bridge with Go proof of concept
How to run or build

~~~~
go get github.com/gorilla/websocket
go get github.com/x/sys/windows
~~~~

Run
~~~~
go run main.go heci_windows.go apfclient.go
~~~~

Build
~~~~
go build -o test.exe main.go heci_windows.go apfclient.go
test.exe
~~~~