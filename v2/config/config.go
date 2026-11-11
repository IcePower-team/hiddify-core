package config

import (
	"bytes"
	context "context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	sync "sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	DNSRemoteTag       = "dns-remote"
	DNSLocalTag        = "dns-local"
	DNSDirectTag       = "dns-direct"
	DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"

	OutboundDirectTag         = "direct §hide§"
	OutboundBypassTag         = "bypass §hide§"
	OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "auto"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"
	WARPConfigTag             = "Hiddify Warp ✅"

	InboundTUNTag   = "tun-in"
	InboundMixedTag = "mixed-in"
	InboundDNSTag   = "dns-in"
)

var (
	OutboundMainProxyTag   = OutboundSelectTag
	PredefinedOutboundTags = []string{OutboundDirectTag, OutboundBypassTag, OutboundBlockTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag}
)

func BuildConfigJson(configOpt HiddifyOptions, input option.Options) (string, error) {
	options, err := BuildConfig(configOpt, input)
	if err != nil {
		return "", err
	}
	// The option structs only marshal their concrete options through the
	// sing-box context marshaler; the stdlib encoder would drop them.
	var buffer bytes.Buffer
	encoder := SJ.NewEncoderContext(singboxContext(), &buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(options)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// TODO include selectors
func BuildConfig(opt HiddifyOptions, input option.Options) (*option.Options, error) {
	var options option.Options
	if opt.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}
	options.DNS = &option.DNSOptions{}
	if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
		OutboundMainProxyTag = WARPConfigTag
	} else {
		OutboundMainProxyTag = OutboundSelectTag
	}
	setClashAPI(&options, &opt)
	setLog(&options, &opt)
	setInbound(&options, &opt)
	setDns(&options, &opt)
	setNTP(&options)
	setRoutingOptions(&options, &opt)
	err := setOutbounds(&options, &input, &opt)

	if err != nil {
		return nil, err
	}
	setFakeDns(&options, &opt)
	addForceDirect(&options, &opt)
	return &options, nil
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		return inp, nil
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	// OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	if opt.Warp.EnableWarp {
		for _, out := range input.Outbounds {
			if warpMap, ok := extractWarpMap(out); ok {
				if key, _ := warpMap["key"].(string); key == "p1" {
					opt.Warp.EnableWarp = false
					break
				}
			}
		}
		if opt.Warp.EnableWarp {
			for _, ep := range input.Endpoints {
				if ep.Type == C.TypeWireGuard {
					if wgOpts, ok := ep.Options.(option.WireGuardEndpointOptions); ok {
						if wgOpts.PrivateKey == opt.Warp.WireguardConfig.PrivateKey || wgOpts.PrivateKey == "p1" {
							opt.Warp.EnableWarp = false
							break
						}
					}
				}
			}
		}
	}
	if opt.Warp.EnableWarp && (opt.Warp.Mode == "warp_over_proxy" || opt.Warp.Mode == "proxy_over_warp") {
		wg := getOrGenerateWarpLocallyIfNeeded(&opt.Warp)
		ep, err := GenerateWarpSingbox(wg, opt.Warp.CleanIP, opt.Warp.CleanPort, opt.Warp.FakePackets, opt.Warp.FakePacketSize, opt.Warp.FakePacketDelay, opt.Warp.FakePacketMode)
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		ep.Tag = WARPConfigTag
		if wgOpts, ok := ep.Options.(option.WireGuardEndpointOptions); ok {
			if opt.Warp.Mode == "warp_over_proxy" {
				wgOpts.DialerOptions.Detour = OutboundSelectTag
			} else {
				wgOpts.DialerOptions.Detour = OutboundDirectTag
			}
			ep.Options = wgOpts
		}
		if err := patchWarpEndpoint(ep, opt, true, nil); err != nil {
			return err
		}
		endpoints = append(endpoints, *ep)
	}
	for _, out := range input.Outbounds {
		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, endpoint, err := patchOutbound(out, *opt, dnsStaticIPs)
		if err != nil {
			return err
		}
		if endpoint != nil {
			// a custom warp outbound converted into an endpoint: it joins
			// the selector like a normal proxy
			if !strings.Contains(endpoint.Tag, "§hide§") && !contains([]string{"direct", "bypass", "block"}, endpoint.Tag) {
				tags = append(tags, endpoint.Tag)
			}
			endpoints = append(endpoints, *endpoint)
			continue
		}
		if outbound == nil {
			continue
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom, C.TypeHInvalidConfig:
			continue
		default:
			if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" && out.Tag == WARPConfigTag {
				continue
			}
			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
			}
			out = patchHiddifyWarpFromConfig(out, *opt)
			outbounds = append(outbounds, out)
		}
	}
	// User endpoints (wireguard/awg/openvpn/...) pass through and join the
	// selector; endpoints resolve as outbounds in the new sing-box API.
	for _, ep := range input.Endpoints {
		if contains(PredefinedOutboundTags, ep.Tag) {
			continue
		}
		if err := patchWarpEndpoint(&ep, opt, true, dnsStaticIPs); err != nil {
			return err
		}
		if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" && ep.Tag == WARPConfigTag {
			continue
		}
		if contains([]string{"direct", "bypass", "block"}, ep.Tag) {
			continue
		}
		if !strings.Contains(ep.Tag, "§hide§") {
			tags = append(tags, ep.Tag)
		}
		ep = patchHiddifyWarpEndpointFromConfig(ep, *opt)
		endpoints = append(endpoints, ep)
	}
	options.Endpoints = endpoints
	testurls := []string{opt.ConnectionTestUrl, "http://captive.apple.com/generate_204", "https://cp.cloudflare.com", "https://google.com/generate_204"}
	if isBlockedConnectionTestUrl(opt.ConnectionTestUrl) {
		testurls = []string{opt.ConnectionTestUrl}
	}
	urlTest := option.Outbound{
		Type: C.TypeURLTest,
		Tag:  OutboundURLTestTag,
		Options: option.URLTestOutboundOptions{
			Outbounds: tags,
			URL:       opt.ConnectionTestUrl,
			URLs:      testurls,
			Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			Tolerance:                 1,
			IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: true,
		},
	}
	defaultSelect := urlTest.Tag

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: option.SelectorOutboundOptions{
			Outbounds:                 append([]string{urlTest.Tag}, tags...),
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}

	outbounds = append([]option.Outbound{selector, urlTest}, outbounds...)

	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:  OutboundDNSTag,
				Type: C.TypeDNS,
			},
			{
				Tag:  OutboundDirectTag,
				Type: C.TypeDirect,
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						TCPFastOpen: false,
						TLSFragment: option.TLSFragmentOptions{
							Enabled: true,
							Size:    opt.TLSTricks.FragmentSize,
							Sleep:   opt.TLSTricks.FragmentSleep,
						},
					},
				},
			},
			{
				Tag:  OutboundBypassTag,
				Type: C.TypeDirect,
			},
			{
				Tag:  OutboundBlockTag,
				Type: C.TypeBlock,
			},
		}...,
	)

	return nil
}

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setClashAPI(options *option.Options, opt *HiddifyOptions) {
	if opt.EnableClashApi {
		if opt.ClashApiSecret == "" {
			opt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", opt.ClashApiPort),
				Secret:             opt.ClashApiSecret,
			},

			CacheFile: &option.CacheFileOptions{
				Enabled: true,
				Path:    "data/clash.db",
			},
		}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    false,
		DisableColor: true,
	}
}

func setInbound(options *option.Options, opt *HiddifyOptions) {
	if opt.EnableTun {
		tunOpts := option.TunInboundOptions{
			Stack:                  opt.TUNStack,
			MTU:                    opt.MTU,
			AutoRoute:              true,
			StrictRoute:            opt.StrictRoute,
			EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",
			// Sniff moved to a sniff route rule in sing-box 1.13: the legacy
			// InboundOptions (sniff/domain_strategy) are rejected at parse time.
		}
		switch opt.IPv6Mode {
		case option.DomainStrategy(dns.DomainStrategyUseIPv4):
			tunOpts.Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
			}
		case option.DomainStrategy(dns.DomainStrategyUseIPv6):
			tunOpts.Address = []netip.Prefix{
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}
		default:
			tunOpts.Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}

		}
		tunInbound := option.Inbound{
			Type:    C.TypeTun,
			Tag:     InboundTUNTag,
			Options: tunOpts,
		}
		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	var bind string
	if opt.AllowConnectionFromLAN {
		bind = "0.0.0.0"
	} else {
		bind = "127.0.0.1"
	}

	bindAddr := badoption.Addr(netip.MustParseAddr(bind))

	options.Inbounds = append(
		options.Inbounds,
		option.Inbound{
			Type: C.TypeMixed,
			Tag:  InboundMixedTag,
			Options: option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     &bindAddr,
					ListenPort: opt.MixedPort,
					// Sniff moved to a sniff route rule in sing-box 1.13: the
					// legacy InboundOptions are rejected at parse time.
				},
				SetSystemProxy: opt.SetSystemProxy,
			},
		},
	)

	options.Inbounds = append(
		options.Inbounds,
		option.Inbound{
			Type: C.TypeDirect,
			Tag:  InboundDNSTag,
			Options: option.DirectInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     &bindAddr,
					ListenPort: opt.LocalDnsPort,
				},
				// OverrideAddress: "1.1.1.1",
				// OverridePort:    53,
			},
		},
	)
}

func setDns(options *option.Options, opt *HiddifyOptions) {
	options.DNS = &option.DNSOptions{
		DNSClientOptions: option.DNSClientOptions{
			IndependentCache: opt.IndependentDNSCache,
		},
		Final: DNSRemoteTag,
		Servers: []option.DNSServerOptions{
			dnsServer(DNSRemoteTag, opt.RemoteDnsAddress, OutboundMainProxyTag),
			dnsServer(DNSTricksDirectTag, "https://dns.cloudflare.com/dns-query", OutboundDirectFragmentTag),
			dnsServer(DNSDirectTag, opt.DirectDnsAddress, OutboundDirectFragmentTag),
			{
				Type: C.DNSTypeLocal,
				Tag:  DNSLocalTag,
				Options: option.LocalDNSServerOptions{
					RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
						DialerOptions: option.DialerOptions{
							Detour: OutboundDirectTag,
						},
					},
				},
			},
		},
	}

	// Static host mappings the old DNSOptions.StaticIPs carried: kept as a
	// package-level map for the xray outbound patching (sing-box 1.13 has
	// no StaticIPs field; the equivalent is a "hosts" DNS server).
	dnsStaticIPs = map[string][]string{
		"time.apple.com":      {"time.g.aaplimg.com", "time.apple.com"},
		"ipinfo.io":           {"ipinfo.io"},
		"dns.cloudflare.com":  {"www.speedtest.net", "cloudflare.com"},
		"ipwho.is":            {"ipwho.is"},
		"api.my-ip.io":        {"api.my-ip.io"},
		"myip.expert":         {"myip.expert"},
		"ip-api.com":          {"ip-api.com"},
		"freeipapi.com":       {"www.speedtest.net", "cloudflare.com"},
		"reallyfreegeoip.org": {"www.speedtest.net", "cloudflare.com"},
		"ipapi.co":            {"www.speedtest.net", "cloudflare.com"},
		"api.ip.sb":           {"www.speedtest.net", "cloudflare.com"},
	}
}

// dnsStaticIPs holds the static host mappings used for xray outbound DNS
// hosts (formerly option.DNSOptions.StaticIPs, removed in sing-box 1.13).
var dnsStaticIPs map[string][]string

// dnsServer builds a DNS server entry for a plain address (IP or hostname,
// optional :port) or an https:// DoH URL, in the transport-based DNS server
// format of sing-box 1.12+. The per-server strategy and address resolver of
// the old format no longer exist; strategy now lives on the DNS rules.
func dnsServer(tag, address, detour string) option.DNSServerOptions {
	if strings.HasPrefix(address, "https://") {
		u, err := url.Parse(address)
		if err == nil && u.Hostname() != "" {
			port := uint16(443)
			if p := u.Port(); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					port = uint16(n)
				}
			}
			return option.DNSServerOptions{
				Type: C.DNSTypeHTTPS,
				Tag:  tag,
				Options: option.RemoteHTTPSDNSServerOptions{
					RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
						RemoteDNSServerOptions: option.RemoteDNSServerOptions{
							DNSServerAddressOptions: option.DNSServerAddressOptions{
								Server:     u.Hostname(),
								ServerPort: port,
							},
							RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
								DialerOptions: option.DialerOptions{
									Detour: detour,
								},
							},
						},
					},
					Path: u.Path,
				},
			}
		}
	}
	server, port := address, uint16(53)
	if h, p, err := net.SplitHostPort(address); err == nil {
		server = h
		if n, err := strconv.Atoi(p); err == nil {
			port = uint16(n)
		}
	}
	return option.DNSServerOptions{
		Type: C.DNSTypeUDP,
		Tag:  tag,
		Options: option.RemoteDNSServerOptions{
			DNSServerAddressOptions: option.DNSServerAddressOptions{
				Server:     server,
				ServerPort: port,
			},
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
				DialerOptions: option.DialerOptions{
					Detour: detour,
				},
			},
		},
	}
}

// dnsRouteAction builds the route action of a DNS rule sending matching
// queries to a server, carrying the old per-server strategy on the action.
func dnsRouteAction(server string, strategy option.DomainStrategy) option.DNSRuleAction {
	return option.DNSRuleAction{
		Action: C.RuleActionTypeRoute,
		RouteOptions: option.DNSRouteActionOptions{
			Server: server,
			AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
				Strategy: strategy,
			},
		},
	}
}

func addForceDirect(options *option.Options, opt *HiddifyOptions) {
	dnsMap := make(map[string]string)

	for _, outbound := range options.Outbounds {
		outboundOptions := outbound.Options
		if outboundOptions == nil {
			continue
		}
		if server, ok := outboundOptions.(option.ServerOptionsWrapper); ok {
			serverDomain := server.TakeServerOptions().Server
			detour := OutboundDirectTag
			if dialer, ok := outboundOptions.(option.DialerOptionsWrapper); ok {
				if server_detour := dialer.TakeDialerOptions().Detour; server_detour != "" {
					detour = server_detour
				}
			}

			if host, err := getHostnameIfNotIP(serverDomain); err == nil {
				if _, ok := dnsMap[host]; !ok || detour == OutboundDirectTag {
					dnsMap[host] = detour
				}
			}
		}
	}

	if len(dnsMap) > 0 {
		unique_dns_detours := make(map[string]bool)
		for _, detour := range dnsMap {
			unique_dns_detours[detour] = true
		}

		for detour := range unique_dns_detours {
			dns_detour := "dns-direct"
			if detour != OutboundDirectTag {
				dns_detour = "dns-" + detour
				options.DNS.Servers = append(options.DNS.Servers, dnsServer(dns_detour, opt.RemoteDnsAddress, detour))
			}

			domains := []string{}
			for domain, d := range dnsMap {
				if d == detour {
					domains = append(domains, domain)
				}
			}

			if len(domains) == 0 {
				continue
			}
			options.DNS.Rules = append(
				[]option.DNSRule{
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							Domain:        domains,
							DNSRuleAction: dnsRouteAction(dns_detour, opt.RemoteDnsDomainStrategy),
						},
					},
				},
				options.DNS.Rules...,
			)
		}

	}

}

func setFakeDns(options *option.Options, opt *HiddifyOptions) {
	if opt.EnableFakeDNS {
		inet4Range := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
		inet6Range := badoption.Prefix(netip.MustParsePrefix("fc00::/18"))
		options.DNS.Servers = append(
			options.DNS.Servers,
			option.DNSServerOptions{
				Type: C.DNSTypeFakeIP,
				Tag:  DNSFakeTag,
				Options: option.FakeIPDNSServerOptions{
					Inet4Range: &inet4Range,
					Inet6Range: &inet6Range,
				},
			},
		)
		options.DNS.Rules = append(
			options.DNS.Rules,
			option.DNSRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultDNSRule{
					Inbound: []string{InboundTUNTag},
					DNSRuleAction: option.DNSRuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.DNSRouteActionOptions{
							Server: DNSFakeTag,
							AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
								DisableCache: true,
							},
						},
					},
				},
			},
		)

	}
}

func setRoutingOptions(options *option.Options, opt *HiddifyOptions) {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	if opt.EnableTun && runtime.GOOS == "android" {
		// routeRules = append(
		// 	routeRules,
		// 	option.Rule{
		// 		Type: C.RuleTypeDefault,

		// 		DefaultOptions: option.DefaultRule{
		// 			Inbound:     []string{InboundTUNTag},
		// 			PackageName: []string{"app.hiddify.com"},
		// 			Outbound:    OutboundBypassTag,
		// 		},
		// 	},
		// )
	}
	if opt.EnableTun && runtime.GOOS == "windows" {
		// routeRules = append(
		// 	routeRules,
		// 	option.Rule{
		// 		Type: C.RuleTypeDefault,
		// 		DefaultOptions: option.DefaultRule{
		// 			ProcessName: []string{"Hiddify", "Hiddify.exe", "HiddifyCli", "HiddifyCli.exe"},
		// 			Outbound:    OutboundBypassTag,
		// 		},
		// 	},
		// )
	}
	// Sniffing moved from the inbounds to a route rule in sing-box 1.13: the
	// legacy inbound sniff fields are rejected at parse time. This rule runs
	// first so later rules can route on the sniffed protocol/domain.
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			Inbound: []string{InboundTUNTag, InboundMixedTag},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			Inbound:    []string{InboundDNSTag},
			RuleAction: routeOutbound(OutboundDNSTag),
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			Port:       []uint16{53},
			RuleAction: routeOutbound(OutboundDNSTag),
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			IPCIDR:     prefixList("10.10.34.0/24"),
			RuleAction: routeOutbound(OutboundMainProxyTag),
		},
	})
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Direct",
	// 		Outbound:  OutboundDirectTag,
	// 	},
	// },
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Global",
	// 		Outbound:  OutboundMainProxyTag,
	// 	},
	// },	}

	if opt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					// GeoIP:    []string{"private"},
					IPIsPrivate: true,
					RuleAction:  routeOutbound(OutboundBypassTag),
				},
			},
		)
	}

	// for _, rule := range opt.Rules {
	// 	routeRule := rule.MakeRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		routeRule.Outbound = OutboundBypassTag
	// 	case "block":
	// 		routeRule.Outbound = OutboundBlockTag
	// 	case "proxy":
	// 		routeRule.Outbound = OutboundMainProxyTag
	// 	}

	// 	if routeRule.IsValid() {
	// 		routeRules = append(
	// 			routeRules,
	// 			option.Rule{
	// 				Type:           C.RuleTypeDefault,
	// 				DefaultOptions: routeRule,
	// 			},
	// 		)
	// 	}

	// 	dnsRule := rule.MakeDNSRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		dnsRule.Server = DNSDirectTag
	// 	case "block":
	// 		dnsRule.Server = DNSBlockTag
	// 		dnsRule.DisableCache = true
	// 	case "proxy":
	// 		if opt.EnableFakeDNS {
	// 			fakeDnsRule := dnsRule
	// 			fakeDnsRule.Server = DNSFakeTag
	// 			fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
	// 			dnsRules = append(dnsRules, fakeDnsRule)
	// 		}
	// 		dnsRule.Server = DNSRemoteTag
	// 	}
	// 	dnsRules = append(dnsRules, dnsRule)
	// }

	parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	var dnsCPttl uint32 = 30000
	if err == nil {
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			Domain: []string{parsedURL.Host},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: DNSRemoteTag,
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						Strategy:     opt.RemoteDnsDomainStrategy,
						RewriteTTL:   &dnsCPttl,
						DisableCache: false,
					},
				},
			},
		})
	}
	dnsRules = append(dnsRules, option.DefaultDNSRule{
		Domain: []string{options.NTP.Server},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server: DNSDirectTag,
				AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
					Strategy:     opt.DirectDnsDomainStrategy,
					RewriteTTL:   &dnsCPttl,
					DisableCache: false,
				},
			},
		},
	})

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			Domain:     []string{options.NTP.Server},
			RuleAction: routeOutbound(OutboundDirectTag),
		},
	})

	if opt.BlockAds {
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geosite-ads"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-category-ads-all.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geosite-malware"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geosite-phishing"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geosite-cryptominers"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-cryptominers.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geoip-phishing"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geoip-malware"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RuleSet: []string{
					"geosite-ads",
					"geosite-malware",
					"geosite-phishing",
					"geosite-cryptominers",
					"geoip-malware",
					"geoip-phishing",
				},
				RuleAction: routeOutbound(OutboundBlockTag),
			},
		})
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RuleSet: []string{
				"geosite-ads",
				"geosite-malware",
				"geosite-phishing",
				"geosite-cryptominers",
			},
			// The old rcode://success block server is gone in sing-box 1.12+;
			// the predefined action answers these queries with an empty
			// NOERROR response instead.
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypePredefined,
				PredefinedOptions: option.DNSRouteActionPredefined{
					Rcode: func() *option.DNSRCode { r := option.DNSRCode(0); return &r }(),
				},
			},
		})

	}
	if opt.Region != "other" {
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			DomainSuffix:  []string{"." + opt.Region},
			DNSRuleAction: dnsRouteAction(DNSDirectTag, opt.DirectDnsDomainStrategy),
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				DomainSuffix: []string{"." + opt.Region},
				RuleAction:   routeOutbound(OutboundDirectTag),
			},
		})
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RuleSet: []string{
				// "geoip-" + opt.Region,
				"geosite-" + opt.Region,
			},
			DNSRuleAction: dnsRouteAction(DNSDirectTag, opt.DirectDnsDomainStrategy),
		})

		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geoip-" + opt.Region},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geoip-" + opt.Region + ".srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    []string{"geosite-" + opt.Region},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-" + opt.Region + ".srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RuleSet: []string{
					"geoip-" + opt.Region,
					"geosite-" + opt.Region,
				},
				RuleAction: routeOutbound(OutboundDirectTag),
			},
		})
	}
	if opt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				Port:       []uint16{443},
				Network:    []string{"udp"},
				RuleAction: routeOutbound(OutboundBlockTag),
			},
		})
	}
	options.Route = &option.RouteOptions{
		Rules:               routeRules,
		Final:               OutboundMainProxyTag,
		AutoDetectInterface: true,
		OverrideAndroidVPN:  true,
		RuleSet:             rulesets,
		// GeoIP: &option.GeoIPOptions{
		// 	Path: opt.GeoIPPath,
		// },
		// Geosite: &option.GeositeOptions{
		// 	Path: opt.GeoSitePath,
		// },
	}
	if opt.EnableDNSRouting {
		for _, dnsRule := range dnsRules {
			if dnsRule.IsValid() {
				options.DNS.Rules = append(
					options.DNS.Rules,
					option.DNSRule{
						Type:           C.RuleTypeDefault,
						DefaultOptions: dnsRule,
					},
				)
			}
		}
	}

}

// routeOutbound builds the route action selecting an outbound. In sing-box
// 1.13 the outbound of a route rule moved from the rule itself into its
// route action.
func routeOutbound(tag string) option.RuleAction {
	return option.RuleAction{
		Action:       C.RuleActionTypeRoute,
		RouteOptions: option.RouteActionOptions{Outbound: tag},
	}
}

// prefixList parses CIDR strings into a prefix list for IPCIDR rule fields.
func prefixList(cidrs ...string) badoption.Listable[*badoption.Prefixable] {
	out := make(badoption.Listable[*badoption.Prefixable], 0, len(cidrs))
	for _, c := range cidrs {
		p := badoption.Prefixable(netip.MustParsePrefix(c))
		out = append(out, &p)
	}
	return out
}

// patchHiddifyWarpFromConfig routes an outbound over WARP (proxy_over_warp
// mode) by setting its dialer detour, when it has none. In the new sing-box
// API the concrete options live in out.Options, so each type is asserted.
func patchHiddifyWarpFromConfig(out option.Outbound, opt HiddifyOptions) option.Outbound {
	if !opt.Warp.EnableWarp || opt.Warp.Mode != "proxy_over_warp" {
		return out
	}
	setDetour := func(detour *string) {
		if *detour == "" {
			*detour = WARPConfigTag
		}
	}
	switch opts := out.Options.(type) {
	case option.DirectOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.HTTPOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.Hysteria2OutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.HysteriaOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.SSHOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.ShadowTLSOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.ShadowsocksOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.ShadowsocksROutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.SOCKSOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.TUICOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.TorOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.TrojanOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.VLESSOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.VMessOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.LegacyWireGuardOutboundOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	case option.SoarOptions:
		setDetour(&opts.DialerOptions.Detour)
		out.Options = opts
	}
	return out
}

// patchHiddifyWarpEndpointFromConfig is the endpoint counterpart of
// patchHiddifyWarpFromConfig: user endpoints (wireguard/awg/openvpn) also
// route over WARP in proxy_over_warp mode.
func patchHiddifyWarpEndpointFromConfig(ep option.Endpoint, opt HiddifyOptions) option.Endpoint {
	if !opt.Warp.EnableWarp || opt.Warp.Mode != "proxy_over_warp" {
		return ep
	}
	setDetour := func(detour *string) {
		if *detour == "" {
			*detour = WARPConfigTag
		}
	}
	switch opts := ep.Options.(type) {
	case option.WireGuardEndpointOptions:
		setDetour(&opts.DialerOptions.Detour)
		ep.Options = opts
	case option.AwgEndpointOptions:
		setDetour(&opts.DialerOptions.Detour)
		ep.Options = opts
	case option.OpenVPNClientEndpointOptions:
		setDetour(&opts.DialerOptions.Detour)
		ep.Options = opts
	}
	return ep
}

var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateRandomString(length int) string {
	// Determine the number of bytes needed
	bytesNeeded := (length*6 + 7) / 8

	// Generate random bytes
	randomBytes := make([]byte, bytesNeeded)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "hiddify"
	}

	// Encode random bytes to base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim padding characters and return the string
	return randomString[:length]
}
