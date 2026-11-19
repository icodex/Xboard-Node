package singbox

import (
	"strconv"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// inboundWithUsers returns a copy of one parsed inbound whose user list is
// rebuilt from the current model users. TLS, transport and multiplex options
// are shared with the original: only the users slice changes, so a user delta
// never re-marshals the whole kernel config.
//
// ok is false for inbound types without a typed mapping (hysteria v1 today);
// the caller then falls back to the full config rebuild.
func inboundWithUsers(inb option.Inbound, nc *model.NodeSpec, users []model.UserSpec) (option.Inbound, bool) {
	switch opts := inb.Options.(type) {
	case *option.VMessInboundOptions:
		next := *opts
		next.Users = make([]option.VMessUser, len(users))
		for i, u := range users {
			next.Users[i] = option.VMessUser{Name: u.UUID, UUID: u.UUID, AlterId: 0}
		}
		inb.Options = &next
		return inb, true

	case *option.VLESSInboundOptions:
		next := *opts
		next.Users = make([]option.VLESSUser, len(users))
		for i, u := range users {
			next.Users[i] = option.VLESSUser{Name: u.UUID, UUID: u.UUID, Flow: nc.Flow}
		}
		inb.Options = &next
		return inb, true

	case *option.TrojanInboundOptions:
		next := *opts
		next.Users = make([]option.TrojanUser, len(users))
		for i, u := range users {
			next.Users[i] = option.TrojanUser{Name: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.Hysteria2InboundOptions:
		next := *opts
		next.Users = make([]option.Hysteria2User, len(users))
		for i, u := range users {
			next.Users[i] = option.Hysteria2User{Name: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.ShadowsocksInboundOptions:
		next := *opts
		next.Users = make([]option.ShadowsocksUser, len(users))
		ss2022, isSS2022 := kernel.SS2022Methods[next.Method]
		for i, u := range users {
			password := u.UUID
			if isSS2022 {
				password = ss2022Password(ss2022.Size, u.UUID)
			}
			next.Users[i] = option.ShadowsocksUser{Name: u.UUID, Password: password}
		}
		inb.Options = &next
		return inb, true

	case *option.TUICInboundOptions:
		next := *opts
		next.Users = make([]option.TUICUser, len(users))
		for i, u := range users {
			next.Users[i] = option.TUICUser{Name: u.UUID, UUID: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.AnyTLSInboundOptions:
		next := *opts
		next.Users = make([]option.AnyTLSUser, len(users))
		for i, u := range users {
			next.Users[i] = option.AnyTLSUser{Name: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.MieruInboundOptions:
		next := *opts
		next.Users = make([]option.MieruUser, len(users))
		for i, u := range users {
			next.Users[i] = option.MieruUser{Name: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.NaiveInboundOptions:
		next := *opts
		next.Users = make([]auth.User, len(users))
		for i, u := range users {
			next.Users[i] = auth.User{Username: strconv.Itoa(u.ID), Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.SocksInboundOptions:
		next := *opts
		next.Users = make([]auth.User, len(users))
		for i, u := range users {
			next.Users[i] = auth.User{Username: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true

	case *option.HTTPMixedInboundOptions:
		next := *opts
		next.Users = make([]auth.User, len(users))
		for i, u := range users {
			next.Users[i] = auth.User{Username: u.UUID, Password: u.UUID}
		}
		inb.Options = &next
		return inb, true
	}
	return option.Inbound{}, false
}
