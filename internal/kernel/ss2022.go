package kernel

// SS2022Method describes a Shadowsocks 2022 cipher: its canonical name and the
// raw key length in bytes. Panel users carry a UUID string whose first Size
// bytes are the raw user key; kernels render it as base64 (config file) or raw
// bytes (xray UserManager).
//
// One table for both kernels: a divergent copy means the two kernels derive
// different keys from the same panel user.
type SS2022Method struct {
	Method string
	Size   int
}

var SS2022Methods = map[string]SS2022Method{
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32},
}
