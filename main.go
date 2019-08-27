package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {

	localAddr := "192.168.60.26"
	remoteHost := "192.168.112.25"

	var sendTime time.Time
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		recvTime := receiveSYNACK(localAddr, remoteHost)

		// 计算时间差
		durat := recvTime.Sub(sendTime)

		// 单位是微秒
		fmt.Printf("--> duration: %v\n", durat)

		wg.Done()
	}()
	sendTime = sendSYN(localAddr, remoteHost, 9992)
	wg.Wait()
	fmt.Printf("------------ send TCP SYN ,%v --------------\n", sendTime)
}

//Send TCP SYN, TCP Three-Way Handshake
func sendSYN(laddr, raddr string, port uint16) time.Time {

	packet := TCPHeader{
		Source:      0xaa47,        // Random ephemeral port  随机端口
		Destination: port,          // 目标端口
		SeqNum:      rand.Uint32(), //序号
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}

	// 组包，序列化
	data := packet.Marshal()

	//计算校验和
	packet.Checksum = Csum(data, to4byte(laddr), to4byte(raddr))

	// 再次序列化
	data = packet.Marshal()

	//fmt.Printf("% x\n", data)

	// 建立连接
	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		log.Fatalf("--> connect remote server fail, Dial: %s\n", err)
	}

	sendTime := time.Now()

	numWrote, err := conn.Write(data)
	if err != nil {
		log.Fatalf("--> send data fail, Write: %s\n", err)
	}
	if numWrote != len(data) {
		log.Fatalf("Short write. Wrote %d/%d bytes\n", numWrote, len(data))
	}

	conn.Close()

	return sendTime
}

// 接受TCP SYN ACK回应
func receiveSYNACK(localAddress, remoteAddress string) time.Time {
	netaddr, err := net.ResolveIPAddr("ip4", localAddress)
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", localAddress, netaddr)
	}

	conn, err := net.ListenIP("ip4:tcp", netaddr)
	if err != nil {
		log.Fatalf("ListenIP: %s\n", err)
	}
	var receiveTime time.Time
	for {
		buf := make([]byte, 1024)
		numRead, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("ReadFrom: %s\n", err)
		}
		if raddr.String() != remoteAddress {
			// this is not the packet we are looking for
			continue
		}
		receiveTime = time.Now()
		//fmt.Printf("Received: % x\n", buf[:numRead])
		tcp := NewTCPHeader(buf[:numRead])
		// Closed port gets RST, open port gets SYN ACK
		if tcp.HasFlag(RST) || (tcp.HasFlag(SYN) && tcp.HasFlag(ACK)) {
			break
		}
	}
	return receiveTime
}
func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}
