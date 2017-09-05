package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Thermi/nfqueue-go/nfqueue"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// program arguments
var queueID = flag.Int("q", 1, "queue id")
var key = flag.Int("k", 0x61, "xor key byte")
var bChecksum = flag.Bool("nocsum", true, "calc checksum bool flag")

func transform(buffer []byte, key byte) {
    for i := 0; i < len(buffer); i++ {
        buffer[i] ^= key
    }
}

func getLayer4(l4 gopacket.Layer, cs bool, l3 gopacket.NetworkLayer) (gopacket.SerializableLayer, error) {
    var err error
    tcp, ok := l4.(*layers.TCP)
    if ok {
        if cs == true {
            err = tcp.SetNetworkLayerForChecksum(l3)
            if err != nil {
                err = fmt.Errorf("failed to checksum. err=%s", err)
                return nil, err
            }
        }
        return tcp, nil
    } else {
        udp, ok := l4.(*layers.UDP)
        if ok {
            if cs == true {
                err = udp.SetNetworkLayerForChecksum(l3)
                if err != nil {
                    err = fmt.Errorf("failed to checksum. err=%s", err)
                    return nil, err
                }
            }
            return udp, nil
        }
    }
    return nil, fmt.Errorf("unsupported layer 4")
}

func cbProcessPacket(payload *nfqueue.Payload) error {
    var err error
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}
    if *bChecksum == true {
        opts.ComputeChecksums = true
    }
    packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.NoCopy)
    if errLayer := packet.ErrorLayer(); errLayer != nil {
        err = fmt.Errorf("failed to decode. err=%s", errLayer)
    } else if app := packet.ApplicationLayer(); app != nil {
        transform(app.Payload(), byte(*key))
        if nl := packet.NetworkLayer(); nl != nil {
            if ipv4, ok := nl.(*layers.IPv4); ok {
                if tl := packet.TransportLayer(); tl != nil {
                    l4, err := getLayer4(tl, *bChecksum, nl)
                    if err != nil {
                        err = fmt.Errorf("failed to get layer 4, err=%s", err)
                    } else {
                        err = gopacket.SerializeLayers(buf, opts, ipv4, l4, gopacket.Payload(app.Payload()))
                        if err != nil {
                            err = fmt.Errorf("failed to serialize. err=%s", err)
                        }
                    }
                }
            }
        }
    }
    if err == nil && len(buf.Bytes()) > 0 {
        payload.SetVerdictModified(nfqueue.NF_ACCEPT, buf.Bytes())
    } else {
        if err != nil {
            log.Println(err)
        }
        payload.SetVerdict(nfqueue.NF_ACCEPT)
    }
    return nil
}

func main() {
    flag.Parse()
    if *queueID > 65535 {
        log.Fatal("valid queue_id range is [0, 65535]")
    }
    if *key > 0xff {
        log.Fatal("valid key range is [0, 255]")
    }
    log.Printf("queue_id=%d, keystring=0x%x", *queueID, *key)

    q := new(nfqueue.Queue)
    q.SetCallback(cbProcessPacket)
    if err := q.Init(); err != nil {
        log.Fatalf("failed to init. err=%s", err)
        return
    }
    if err := q.Unbind(syscall.AF_INET); err != nil {
        log.Fatalf("failed to unbind. err=%s", err)
        return
    }
    if err := q.Bind(syscall.AF_INET); err != nil {
        log.Fatalf("failed to bind. err=%s", err)
        return
    }
    if err := q.CreateQueue(uint16(*queueID)); err != nil {
        log.Fatalf("failed to create queue %d. err=%s", *queueID, err)
        return
    }
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        for sig := range c {
            _ = sig
            q.StopLoop()
        }
    }()

    log.Println("init finished, wait for processing")
    if err := q.Loop(); err != nil {
        log.Fatalf("failed to process. err=%s", err)
        return
    }

    log.Println("destroy queue")
    if err := q.DestroyQueue(); err != nil {
        log.Fatalf("failed to destroy queue. err=%s", err)
        return
    }
    log.Println("close handle")
    q.Close()
}
