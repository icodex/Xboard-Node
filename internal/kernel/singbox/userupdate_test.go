package singbox

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/cedar2025/xboard-node/internal/model"
)

// A user delta must rewrite only the users slice: TLS/transport pointers come
// from the already parsed options, so no config JSON round-trip happens.
func TestInboundWithUsers_VLESSKeepsParsedOptions(t *testing.T) {
	tls := &option.InboundTLSOptions{ServerName: "keep.example.com"}
	inb := option.Inbound{
		Type:    "vless",
		Tag:     "vless-in",
		Options: &option.VLESSInboundOptions{TLS: tls},
	}
	users := []model.UserSpec{
		{ID: 1, UUID: "11111111-1111-1111-1111-111111111111"},
		{ID: 2, UUID: "22222222-2222-2222-2222-222222222222"},
	}

	next, ok := inboundWithUsers(inb, &model.NodeSpec{Flow: "xtls-rprx-vision"}, users)
	if !ok {
		t.Fatal("vless must have a typed user mapping")
	}
	opts, ok := next.Options.(*option.VLESSInboundOptions)
	if !ok {
		t.Fatalf("options type lost: %T", next.Options)
	}
	if opts.TLS != tls {
		t.Fatal("TLS options must be shared with the parsed inbound")
	}
	if len(opts.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(opts.Users))
	}
	if opts.Users[1].Name != users[1].UUID || opts.Users[1].UUID != users[1].UUID {
		t.Fatalf("user mapping wrong: %+v", opts.Users[1])
	}
	if opts.Users[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q", opts.Users[0].Flow)
	}
}

func TestInboundWithUsers_Shadowsocks2022Key(t *testing.T) {
	const method = "2022-blake3-aes-128-gcm"
	uuid := "11111111-1111-1111-1111-111111111111"
	inb := option.Inbound{
		Type:    "shadowsocks",
		Tag:     "ss-in",
		Options: &option.ShadowsocksInboundOptions{Method: method},
	}

	next, ok := inboundWithUsers(inb, &model.NodeSpec{Cipher: method}, []model.UserSpec{{ID: 1, UUID: uuid}})
	if !ok {
		t.Fatal("shadowsocks must have a typed user mapping")
	}
	opts := next.Options.(*option.ShadowsocksInboundOptions)
	raw := make([]byte, 16)
	copy(raw, uuid)
	if want := base64.StdEncoding.EncodeToString(raw); opts.Users[0] != (option.ShadowsocksUser{Name: uuid, Password: want}) {
		t.Fatalf("user = %+v, want password=%q", opts.Users[0], want)
	}
}

func TestInboundWithUsers_NaiveUsernameIsID(t *testing.T) {
	inb := option.Inbound{
		Type:    "naive",
		Tag:     "naive-in",
		Options: &option.NaiveInboundOptions{},
	}
	next, ok := inboundWithUsers(inb, &model.NodeSpec{}, []model.UserSpec{{ID: 42, UUID: "secret"}})
	if !ok {
		t.Fatal("naive must have a typed user mapping")
	}
	users := next.Options.(*option.NaiveInboundOptions).Users
	if len(users) != 1 || users[0].Username != "42" || users[0].Password != "secret" {
		t.Fatalf("users = %+v", users)
	}
}

func TestInboundWithUsers_UnsupportedFallsBack(t *testing.T) {
	// Hysteria v1 users carry an opaque auth blob; the caller must use the
	// full config rebuild instead of guessing the encoding.
	cases := []option.Inbound{
		{Type: "hysteria", Tag: "hy1", Options: &option.HysteriaInboundOptions{}},
		{Type: "vless", Tag: "value-options", Options: option.VLESSInboundOptions{}},
	}
	for _, inb := range cases {
		if _, ok := inboundWithUsers(inb, &model.NodeSpec{}, []model.UserSpec{{ID: 1, UUID: "u"}}); ok {
			t.Fatalf("%s must fall back to the rebuild path", inb.Type)
		}
	}
}
