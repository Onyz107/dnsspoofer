package dns

import (
	"errors"

	"github.com/google/gopacket"
)

func (pp *ParsedPacket) Serialize() ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var layers []gopacket.SerializableLayer
	switch pp.IPVersion {
	case 4:
		pp.UDP.SetNetworkLayerForChecksum(pp.IPv4)
		layers = append(layers, pp.IPv4)
	case 6:
		pp.UDP.SetNetworkLayerForChecksum(pp.IPv6)
		layers = append(layers, pp.IPv6)
	default:
		return nil, ErrInvalidIPVersion
	}
	layers = append(layers, pp.UDP, pp.DNS)

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, errors.Join(ErrSerializeLayers, err)
	}

	return buffer.Bytes(), nil
}
