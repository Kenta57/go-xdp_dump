package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"bufio"
	"time"
	"path/filepath"
	"io"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpDump ./bpf/xdp_dump.c -- -I../header

var iface string

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map `ebpf:"perfmap"`
}

type perfEventItem struct {
	SrcIp uint32
	DstIp uint32
	SrcPort uint16
	DstPort uint16
	SeqNum uint32
	AckNum uint32
	TimeStamp uint64
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	defer func() {
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
	}()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("All TCP connections coming to this host will be dumped here.")
	fmt.Println()
	var (
		received int = 0
		lost int = 0
	)

	go func() {
		// ファイル名とバッファサイズを設定
		filePath := "log/tcp_info_seq.bin"
		bufferSize := 4096 // バイト単位で設定

		// ファイルをオープンして書き込み用のWriterを作成
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("ファイルをオープンできませんでした:", err)
			return
		}
		defer file.Close()

		writer := bufio.NewWriterSize(file, bufferSize)

		// ローテーションタイミングを設定
		rotationDuration := time.Minute // 30分ごとにローテーション
		rotationTimer := time.NewTimer(rotationDuration)

		var event perfEventItem
		for {
			select {
				case <-rotationTimer.C:
					// ローテーションタイミングでファイルをクローズ・リネーム・再オープン
					err = writer.Flush()
					if err != nil {
						fmt.Println("バッファのフラッシュエラー:", err)
						return
					}
					file.Close()
					rotateFile(filePath)
					file, _ = os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
					writer = bufio.NewWriter(file)
					rotationTimer.Reset(rotationDuration)

					fmt.Println("\nSummary:")
					fmt.Printf("\t%d Event(s) Received\n", received)
					fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
				
				default:
					evnt, err := perfEvent.Read()
					if err != nil {
						if errors.Unwrap(err) == perf.ErrClosed {
							break
						}
						panic(err)
					}
					reader := bytes.NewReader(evnt.RawSample)
					if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
						if err == io.EOF {
							continue
						}
						fmt.Printf("%v", err)
						panic(err)
					}

					// 構造体をバイナリに変換してバッファに書き込む
					err = binary.Write(writer, binary.LittleEndian, &event)
					if err != nil {
						fmt.Println("ファイルへの書き込みエラー:", err)
						return
					}

					// バッファサイズを超えたらフラッシュして書き込み
					writer.Flush()
		

					// メッセージをバッファに書き込む
					received += len(evnt.RawSample)
					lost += int(evnt.LostSamples)
			}
		}
	}()
	<-ctrlC
	perfEvent.Close()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exit...")
}

func intToIpv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8 ) | (value >> 8)
}

// ファイルのローテーションを行う関数
func rotateFile(filePath string) {
	// ファイルのリネーム
	fileName := filepath.Base(filePath)
	fileDir := filepath.Dir(filePath)
	newFilePath := fmt.Sprintf("%s/%s.%s", fileDir, time.Now().Format("2006-01-02-15-04-05"), fileName)
	os.Rename(filePath, newFilePath)

	// 新しいファイルを作成
	file, _ := os.Create(filePath)
	file.Close()
}
