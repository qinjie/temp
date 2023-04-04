// Original Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// Modification Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause
package main
import (
    "bufio"
    // "bytes"
    // crypto_rand "crypto/rand"
    // "encoding/binary"
    "flag"
    "fmt"
    // "hash/crc64"
    "io"
    "io/ioutil"
    "log"
    // math_rand "math/rand"
    "net"
    "os"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/examples/util"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/tcpassembly"
    "github.com/google/gopacket/tcpassembly/tcpreader"
)
var fwdDestination = flag.String("destination", "", "Destination of the forwarded requests.")
var fwdPerc = flag.Float64("percentage", 100, "Must be between 0 and 100.")
var fwdBy = flag.String("percentage-by", "", "Can be empty. Otherwise, valid values are: header, remoteaddr.")
var fwdHeader = flag.String("percentage-by-header", "", "If percentage-by is header, then specify the header here.")
var reqPort = flag.Int("filter-request-port", 80, "Must be between 0 and 65535.")
// modified
type tcpStreamFactory struct{}
// tcpStream will handle the actual decoding of http requests.
type tcpStream struct {
    net, transport gopacket.Flow
    r              tcpreader.ReaderStream
}
func (f *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
    tStream := &tcpStream{
        net:       net,
        transport: transport,
        r:         tcpreader.NewReaderStream(),
    }
    go tStream.run()
    // ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
    return &tStream.r
}
func (t *tcpStream) run() {
    buf := bufio.NewReader(&t.r)
    for {
        reqSourceIP := t.net.Src().String()
        reqDestionationIP := t.transport.Dst().String()
        data, err := ioutil.ReadAll(buf)
        if err == io.EOF {
            return
        } else if err != nil {
            log.Fatal(err)
            return
        } else {
            if len(data) == 0 {
                time.Sleep(time.Millisecond * 10)
                continue
            }
            fmt.Println("data: ", len(data))
            go forwardRequest(reqSourceIP, reqDestionationIP, data)
        }
    }
}
// forward data
func forwardRequest(reqSourceIP string, reqDestionationIP string, data []byte){
    connStat := fmt.Sprintf("%s:%d", string(*fwdDestination), int(*reqPort))
    conn, err := net.Dial("tcp", connStat)
    if err != nil {
        log.Fatal(err)
        return
    }
    defer conn.Close()
    fmt.Printf("forwarding traffic from %s", reqSourceIP)
    conn.Write(data)
}
// Listen for incoming connections.
func openTCPClient() {
    ln, err := net.Listen("tcp", ":4789")
    if err != nil {
        // If TCP listener cannot be established, NLB health checks would fail
        // For this reason, we OS.exit
        log.Println("Error listening on TCP", ":", err)
        os.Exit(1)
    }
    log.Println("Listening on TCP 4789")
    for {
        // Listen for an incoming connection and close it immediately.
        conn, _ := ln.Accept()
        conn.Close()
    }
}
// main
func main() {
    defer util.Run()()
    var handle *pcap.Handle
    var err error
    flag.Parse()
    //labels validation
    if *fwdPerc > 100 || *fwdPerc < 0 {
        err = fmt.Errorf("Flag percentage is not between 0 and 100. Value: %f.", *fwdPerc)
    } else if *fwdBy != "" && *fwdBy != "header" && *fwdBy != "remoteaddr" {
        err = fmt.Errorf("Flag percentage-by (%s) is not valid.", *fwdBy)
    } else if *fwdBy == "header" && *fwdHeader == "" {
        err = fmt.Errorf("Flag percentage-by is set to header, but percentage-by-header is empty.")
    } else if *reqPort > 65535 || *reqPort < 0 {
        err = fmt.Errorf("Flag filter-request-port is not between 0 and 65535. Value: %f.", *fwdPerc)
    }
    if err != nil {
        log.Fatal(err)
    }
    // Set up pcap packet capture
    log.Printf("Starting capture on interface vxlan0")
    handle, err = pcap.OpenLive("vxlan0", 8951, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    // Set up BPF filter
    BPFFilter := fmt.Sprintf("%s%d", "tcp and dst port ", *reqPort)
    if err := handle.SetBPFFilter(BPFFilter); err != nil {
        log.Fatal(err)
    }
    // Set up assembly
    streamFactory := &tcpStreamFactory{}
    streamPool := tcpassembly.NewStreamPool(streamFactory)
    assembler := tcpassembly.NewAssembler(streamPool)
    log.Println("reading in packets")
    // Read in packets, pass to assembler.
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := packetSource.Packets()
    ticker := time.Tick(time.Minute)
    //Open a TCP Client, for NLB Health Checks only
    go openTCPClient()
    for {
        select {
        case packet := <-packets:
            // A nil packet indicates the end of a pcap file.
            if packet == nil {
                return
            }
            if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
                log.Println("Unusable packet")
                continue
            }
            tcp := packet.TransportLayer().(*layers.TCP)
            assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
        case <-ticker:
            // Every minute, flush connections that haven't seen activity in the past 1 minute.
            assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
        }
    }
}
