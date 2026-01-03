package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func createNFTRule(tableName string, family nftables.TableFamily, chainName string, hook *nftables.ChainHook,
	key expr.MetaKey, offset uint32, queue uint16, ifaceIndex uint32) (func() error, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, errors.Join(ErrNewNetlinkConn, err)
	}

	table := &nftables.Table{
		Name:   tableName,
		Family: family,
	}
	conn.AddTable(table)

	policy := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}
	conn.AddChain(chain)

	dataBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(dataBuf, ifaceIndex)
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// match ingoing/outgoing interface
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: dataBuf},

			// meta l4proto udp
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_UDP}},

			// udp sport/dport 53
			&expr.Payload{DestRegister: 2, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
			&expr.Cmp{Register: 2, Op: expr.CmpOpEq, Data: []byte{0x00, 0x35}},

			// nfqueue
			&expr.Queue{Num: queue, Flag: expr.QueueFlagBypass},
		},
	}

	conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return nil, errors.Join(ErrFlush, err)
	}

	return func() error {
		conn, err := nftables.New()
		if err != nil {
			return errors.Join(ErrNewNetlinkConn, err)
		}

		conn.DelTable(table)
		if err := conn.Flush(); err != nil {
			return errors.Join(ErrFlush, err)
		}
		return nil
	}, nil
}

// AddDNSQueue creates nftables rules to capture DNS packets and send them to a netfilter queue.
// It supports filtering for IPv4, IPv6, or both, and can target either DNS requests or responses.
//
// Returns an error if an invalid parameter is provided, or if creating or flushing nftables rules fails.
func AddDNSQueue(ipMode IPMode, iface *net.Interface, spoofMode SpoofMode, scope Scope, queue uint16) (func() error, error) {
	var families map[string]nftables.TableFamily
	switch ipMode {
	case IPv4Only:
		logger.Logger.Debug("filtering only for IPv4")
		families = map[string]nftables.TableFamily{
			"dnsspoof_IPv4_filter": nftables.TableFamilyIPv4,
		}
	case IPv6Only:
		logger.Logger.Debug("filtering only for IPv6")
		families = map[string]nftables.TableFamily{
			"dnsspoof_IPv6_filter": nftables.TableFamilyIPv6,
		}
	case IPv4AndIPv6:
		logger.Logger.Debug("filtering for both IPv4 and IPv6")
		families = map[string]nftables.TableFamily{
			"dnsspoof_IPv4_filter": nftables.TableFamilyIPv4,
			"dnsspoof_IPv6_filter": nftables.TableFamilyIPv6,
		}
	default:
		return nil, ErrInvalidIPMode
	}

	var key expr.MetaKey
	var hook *nftables.ChainHook
	var offset uint32
	switch spoofMode {
	case Aggressive:
		key = expr.MetaKeyOIF           // sniff from output interface
		offset = udpDestPortOffset      // dport
		hook = nftables.ChainHookOutput // OUTPUT chain
		logger.Logger.Debug("filtering for DNS requests", "key", "OIF", "offset", "2 (dport)", "hook", "OUTPUT")
	case Passive:
		key = expr.MetaKeyIIF          // sniff from input interface
		offset = udpSourcePortOffset   // sport
		hook = nftables.ChainHookInput // INPUT chain
		logger.Logger.Debug("filtering for DNS responses", "key", "IIF", "offset", "1 (sport)", "hook", "INPUT")
	default:
		return nil, ErrInvalidSpoofMode
	}

	if scope == Remote {
		hook = nftables.ChainHookForward
		logger.Logger.Debug("filtering for remote DNS packets", "hook", "FORWARD")
	} else if scope != Local {
		return nil, ErrInvalidScope
	}

	var cleanups []func() error
	for tableName, family := range families {
		cleanup, err := createNFTRule(tableName, family,
			fmt.Sprintf("dnsspoof_chain_%s_%s_%s", spoofMode.String(), scope.String(), uuid.New().String()),
			hook, key, offset, queue, uint32(iface.Index))

		if err != nil {
			return nil, err
		}

		cleanups = append(cleanups, cleanup)
	}

	return func() error {
		var err error
		once.Do(func() {
			var errs []error
			for _, c := range cleanups {
				if e := c(); e != nil {
					errs = append(errs, e)
				}
			}
			err = errors.Join(errs...)
		})
		return err
	}, nil
}
