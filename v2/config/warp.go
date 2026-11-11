package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/bepass-org/warp-plus/warp"
	C "github.com/sagernet/sing-box/constant"

	// "github.com/bepass-org/wireguard-go/warp"
	"github.com/hiddify/hiddify-core/v2/db"

	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	hiddify "github.com/sagernet/wireguard-go/hiddify"
)

type SingboxConfig struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	Server        string   `json:"server"`
	ServerPort    int      `json:"server_port"`
	LocalAddress  []string `json:"local_address"`
	PrivateKey    string   `json:"private_key"`
	PeerPublicKey string   `json:"peer_public_key"`
	Reserved      []int    `json:"reserved"`
	MTU           int      `json:"mtu"`
}

func wireGuardToSingbox(wgConfig WarpWireguardConfig, server string, port uint16) (*T.Endpoint, error) {
	clientID, _ := base64.StdEncoding.DecodeString(wgConfig.ClientID)
	if len(clientID) < 2 {
		clientID = []byte{0, 0, 0}
	}
	var addresses []netip.Prefix
	for _, addr := range []string{wgConfig.LocalAddressIPv4 + "/24", wgConfig.LocalAddressIPv6 + "/128"} {
		if addr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, err // Handle the error appropriately
		}
		addresses = append(addresses, prefix)
	}
	// WireGuard is an endpoint in sing-box 1.12+; the legacy outbound cannot
	// carry noise (fake) packets, so WARP is built as an endpoint.
	ep := T.Endpoint{
		Type: C.TypeWireGuard,
		Tag:  "WARP",
		Options: T.WireGuardEndpointOptions{
			Address:    addresses,
			PrivateKey: wgConfig.PrivateKey,
			MTU:        1330,
			Peers: []T.WireGuardPeer{{
				Address:   server,
				Port:      port,
				PublicKey: wgConfig.PeerPublicKey,
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.IPv4Unspecified(), 0),
					netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				},
				Reserved: []uint8{clientID[0], clientID[1], clientID[2]},
			}},
		},
	}
	return &ep, nil
}

func getRandomIP() string {
	ipPort, err := warp.RandomWarpEndpoint(true, true)
	if err == nil {
		return ipPort.Addr().String()
	}
	return "engage.cloudflareclient.com"
}

func generateWarp(license string, host string, port uint16, fakePackets string, fakePacketsSize string, fakePacketsDelay string, fakePacketsMode string) (*T.Endpoint, error) {
	_, _, wgConfig, err := GenerateWarpInfo(license, "", "")
	if err != nil {
		return nil, err
	}
	if wgConfig == nil {
		return nil, fmt.Errorf("invalid warp config")
	}

	return GenerateWarpSingbox(*wgConfig, host, port, fakePackets, fakePacketsSize, fakePacketsDelay, fakePacketsMode)
}

func GenerateWarpSingbox(wgConfig WarpWireguardConfig, host string, port uint16, fakePackets string, fakePacketsSize string, fakePacketsDelay string, fakePacketMode string) (*T.Endpoint, error) {
	if host == "" {
		host = "auto4"
	}

	if (host == "auto" || host == "auto4" || host == "auto6") && fakePackets == "" {
		fakePackets = "1-3"
	}
	if fakePackets != "" && fakePacketsSize == "" {
		fakePacketsSize = "10-30"
	}
	if fakePackets != "" && fakePacketsDelay == "" {
		fakePacketsDelay = "10-30"
	}
	singboxConfig, err := wireGuardToSingbox(wgConfig, host, port)
	if err != nil {
		fmt.Printf("%v %v", singboxConfig, err)
		return nil, err
	}

	// Noise (fake) packets moved into the endpoint's Noise options in the
	// new WireGuard endpoint API.
	if fakePackets != "" {
		if opts, ok := singboxConfig.Options.(T.WireGuardEndpointOptions); ok {
			opts.Noise.FakePacket = hiddify.FakePacketOptions{
				Enabled: true,
				Count:   parseNoiseRange(fakePackets),
				Size:    parseNoiseRange(fakePacketsSize),
				Delay:   parseNoiseRange(fakePacketsDelay),
				Mode:    fakePacketMode,
			}
			singboxConfig.Options = opts
		}
	}

	return singboxConfig, nil
}

// parseNoiseRange parses a "min-max" range string (e.g. "1-3") into a
// hiddify.Range; a single number becomes a fixed range, empty means zero.
func parseNoiseRange(s string) hiddify.Range {
	if s == "" {
		return hiddify.Range{}
	}
	parts := strings.SplitN(s, "-", 2)
	from, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	to := from
	if len(parts) == 2 {
		to, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	}
	return hiddify.Range{From: int32(from), To: int32(to)}
}

func GenerateWarpInfo(license string, oldAccountId string, oldAccessToken string) (*warp.Identity, string, *WarpWireguardConfig, error) {
	if oldAccountId != "" && oldAccessToken != "" {
		err := warp.DeleteDevice(oldAccessToken, oldAccountId)
		if err != nil {
			fmt.Printf("Error in removing old device: %v\n", err)
		} else {
			fmt.Printf("Old Device Removed")
		}
	}
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	identity, err := warp.CreateIdentityOnly(l, license)
	res := "Error!"
	var warpcfg WarpWireguardConfig
	if err == nil {
		res = "Success"
		res = fmt.Sprintf("Warp+ enabled: %t\n", identity.Account.WarpPlus)
		res += fmt.Sprintf("\nAccount type: %s\n", identity.Account.AccountType)
		warpcfg = WarpWireguardConfig{
			PrivateKey:       identity.PrivateKey,
			PeerPublicKey:    identity.Config.Peers[0].PublicKey,
			LocalAddressIPv4: identity.Config.Interface.Addresses.V4,
			LocalAddressIPv6: identity.Config.Interface.Addresses.V6,
			ClientID:         identity.Config.ClientID,
		}
	}

	return &identity, res, &warpcfg, err
}

func getOrGenerateWarpLocallyIfNeeded(warpOptions *WarpOptions) WarpWireguardConfig {
	if warpOptions.WireguardConfig.PrivateKey != "" {
		return warpOptions.WireguardConfig
	}
	table := db.GetTable[WarpOptions]()
	dbWarpOptions, err := table.Get(warpOptions.Id)
	if err == nil && dbWarpOptions.WireguardConfig.PrivateKey != "" {
		return dbWarpOptions.WireguardConfig
	}
	license := ""
	if len(warpOptions.Id) == 26 { // warp key is 26 characters long
		license = warpOptions.Id
	} else if len(warpOptions.Id) > 28 && warpOptions.Id[2] == '_' { // warp key is 26 characters long
		license = warpOptions.Id[3:]
	}

	accountidentity, _, wireguardConfig, err := GenerateWarpInfo(license, warpOptions.Account.AccountID, warpOptions.Account.AccessToken)
	if err != nil {
		return WarpWireguardConfig{}
	}
	warpOptions.Account = WarpAccount{
		AccountID:   accountidentity.ID,
		AccessToken: accountidentity.Token,
	}
	warpOptions.WireguardConfig = *wireguardConfig
	table.UpdateInsert(warpOptions)

	return *wireguardConfig
}

// extractWarpMap returns the "warp" object of a Hiddify custom outbound, if any.
// In the new sing-box API a custom outbound arrives as hinvalid options holding
// the original JSON, since "custom" is no longer a registered outbound type.
func extractWarpMap(base option.Outbound) (map[string]any, bool) {
	if base.Type == C.TypeHInvalidConfig {
		if invalid, ok := base.Options.(*option.HInvalidOptions); ok && invalid.OriginalType == C.TypeCustom {
			if raw, ok := invalid.InvalidConfig.(json.RawMessage); ok {
				var obj map[string]any
				if json.Unmarshal(raw, &obj) == nil {
					if warpMap, ok := obj["warp"].(map[string]any); ok {
						return warpMap, true
					}
				}
			}
		}
		return nil, false
	}
	if base.Type == C.TypeCustom {
		if m, ok := base.Options.(map[string]any); ok {
			if warpMap, ok := m["warp"].(map[string]any); ok {
				return warpMap, true
			}
		}
	}
	return nil, false
}

func warpMapPort(warpMap map[string]any) uint16 {
	switch v := warpMap["port"].(type) {
	case uint16:
		return v
	case float64:
		return uint16(v)
	case int:
		return uint16(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return uint16(n)
		}
	}
	return 0
}

// warpOutboundToEndpoint converts a Hiddify custom warp outbound into a
// WireGuard endpoint. It returns (endpoint, true) when base is a custom warp
// outbound that should be converted now, and (nil, false) when it is not a
// warp outbound, or when a saved-key warp must stay untouched until the final
// pass (final=false, same as the old patchWarp behaviour).
func warpOutboundToEndpoint(base option.Outbound, configOpt *HiddifyOptions, final bool, staticIpsDns map[string][]string) (*option.Endpoint, bool, error) {
	warpMap, ok := extractWarpMap(base)
	if !ok {
		return nil, false, nil
	}
	key, _ := warpMap["key"].(string)
	host, _ := warpMap["host"].(string)
	port := warpMapPort(warpMap)
	detour, _ := warpMap["detour"].(string)
	fakePackets, _ := warpMap["fake_packets"].(string)
	fakePacketsSize, _ := warpMap["fake_packets_size"].(string)
	fakePacketsDelay, _ := warpMap["fake_packets_delay"].(string)
	fakePacketsMode, _ := warpMap["fake_packets_mode"].(string)

	isSavedKey := len(key) > 1 && key[0] == 'p'

	if (configOpt == nil || !final) && isSavedKey {
		return nil, false, nil
	}
	var wireguardConfig WarpWireguardConfig
	if isSavedKey {
		var warpOpt *WarpOptions
		if key == "p1" {
			warpOpt = &configOpt.Warp
		} else if key == "p2" {
			warpOpt = &configOpt.Warp2
		} else {
			warpOpt = &WarpOptions{
				Id: key,
			}
		}
		warpOpt.Id = key

		wireguardConfig = getOrGenerateWarpLocallyIfNeeded(warpOpt)
	} else {
		_, _, wgConfig, err := GenerateWarpInfo(key, "", "")
		if err != nil {
			return nil, false, err
		}
		wireguardConfig = *wgConfig
	}
	ep, err := GenerateWarpSingbox(wireguardConfig, host, port, fakePackets, fakePacketsSize, fakePacketsDelay, fakePacketsMode)
	if err != nil {
		fmt.Printf("Error generating warp config: %v", err)
		return nil, false, err
	}
	ep.Tag = base.Tag
	if opts, ok := ep.Options.(T.WireGuardEndpointOptions); ok {
		opts.DialerOptions.Detour = detour
		ep.Options = opts
	}
	if err := patchWarpEndpoint(ep, configOpt, final, staticIpsDns); err != nil {
		return nil, false, err
	}
	return ep, true, nil
}

// patchWarpEndpoint applies the final-pass fixes to a WireGuard endpoint:
// auto/random hosts are resolved to a concrete WARP IP, an empty port gets a
// random WARP port, and a detoured endpoint drops its noise packets and gets a
// smaller MTU. It is a no-op unless final is true.
func patchWarpEndpoint(ep *option.Endpoint, configOpt *HiddifyOptions, final bool, staticIpsDns map[string][]string) error {
	if !final || ep.Type != C.TypeWireGuard {
		return nil
	}
	opts, ok := ep.Options.(option.WireGuardEndpointOptions)
	if !ok || len(opts.Peers) == 0 {
		return nil
	}
	host := opts.Peers[0].Address

	if host == "default" || host == "random" || host == "auto" || host == "auto4" || host == "auto6" || isBlockedDomain(host) {
		if host != "auto4" {
			if host == "auto6" { //|| common.u.CanConnectIPv6() {
				randomIpPort, _ := warp.RandomWarpEndpoint(false, true)
				host = randomIpPort.Addr().String()
			}
		}
		if host != "auto6" {
			randomIpPort, _ := warp.RandomWarpEndpoint(true, false)
			host = randomIpPort.Addr().String()
		}
		opts.Peers[0].Address = host
	}
	if opts.Peers[0].Port == 0 {
		port := warp.RandomWarpPort()
		opts.Peers[0].Port = port
	}

	if opts.DialerOptions.Detour != "" {
		if opts.MTU < 100 {
			opts.MTU = 1280
		}
		opts.Noise.FakePacket = hiddify.FakePacketOptions{}
	}
	ep.Options = opts
	return nil
}
