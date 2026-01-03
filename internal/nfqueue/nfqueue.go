package nfqueue

import (
	"context"
	"errors"

	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/florianl/go-nfqueue/v2"
)

func GetPacketChan(ctx context.Context, nfq *nfqueue.Nfqueue) (<-chan Packet, error) {
	packetCh := make(chan Packet, 1024)

	handler := func(attr nfqueue.Attribute) int {
		if attr.PacketID == nil || attr.Payload == nil {
			return 0
		}

		payload := *attr.Payload
		pkt := Packet{
			PacketID:  *attr.PacketID,
			Payload:   payload,
			IPVersion: uint32(payload[0] >> 4),
		}

		select {
		case packetCh <- pkt:
		case <-ctx.Done():
			nfq.SetVerdict(pkt.PacketID, nfqueue.NfAccept)
			return 0
		default:
			logger.Logger.Warn("packet channel full, dropping packet")
			nfq.SetVerdict(pkt.PacketID, nfqueue.NfDrop)
		}

		return 0
	}

	err := nfq.RegisterWithErrorFunc(
		ctx,
		handler,
		func(e error) int {
			logger.Logger.Error(ErrNFQUEUERead, "err", e)
			return 0
		},
	)
	if err != nil {
		nfq.Close()
		return nil, errors.Join(ErrRegisterFunc, err)
	}

	go func() {
		<-ctx.Done()
		nfq.Close()
		close(packetCh)
	}()

	return packetCh, nil
}
