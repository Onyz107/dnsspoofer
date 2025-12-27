package redirect

import (
	"net"

	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nftables"
)

func DNS(ipMode nftables.IPMode, iface *net.Interface,
	spoofMode nftables.SpoofMode, scope nftables.Scope, queue uint16) (func() error, error) {
	logger.Logger.Info(
		"Redirecting DNS packets",
		"ip_mode", ipMode.String(),
		"spoof_mode", spoofMode.String(),
		"scope", scope.String(),
		"interface", iface.Name,
		"queue", queue,
	)
	return nftables.AddDNSQueue(ipMode, iface, spoofMode, scope, queue)
}
