package config

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

//go:embed config.json.template
var configByte []byte

// singboxContext builds the context carrying the sing-box option registries,
// which the context-aware option marshal/unmarshal needs.
func singboxContext() context.Context {
	return include.Context(context.Background())
}

func ParseConfig(path string, debug bool) ([]byte, error) {
	content, err := os.ReadFile(path)
	os.Chdir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return ParseConfigContent(string(content), debug, nil, false)
}

func ParseConfigContentToOptions(contentstr string, debug bool, configOpt *HiddifyOptions, fullConfig bool) (*option.Options, error) {
	content, err := ParseConfigContent(contentstr, debug, configOpt, fullConfig)
	if err != nil {
		return nil, err
	}
	options, err := SJ.UnmarshalExtendedContext[option.Options](singboxContext(), content)
	if err != nil {
		return nil, err
	}
	return &options, nil
}

func ParseConfigContent(contentstr string, debug bool, configOpt *HiddifyOptions, fullConfig bool) ([]byte, error) {
	if configOpt == nil {
		configOpt = DefaultHiddifyOptions()
	}
	content := []byte(contentstr)
	var jsonObj map[string]interface{} = make(map[string]interface{})

	fmt.Printf("Convert using json\n")
	var tmpJsonResult any
	jsonDecoder := json.NewDecoder(SJ.NewCommentFilter(bytes.NewReader(content)))
	if err := jsonDecoder.Decode(&tmpJsonResult); err == nil {
		if tmpJsonObj, ok := tmpJsonResult.(map[string]interface{}); ok {
			if tmpJsonObj["outbounds"] == nil {
				jsonObj["outbounds"] = []interface{}{jsonObj}
			} else {
				if fullConfig || (configOpt != nil && configOpt.EnableFullConfig) {
					jsonObj = tmpJsonObj
				} else {
					jsonObj["outbounds"] = tmpJsonObj["outbounds"]
				}
			}
		} else if jsonArray, ok := tmpJsonResult.([]map[string]interface{}); ok {
			jsonObj["outbounds"] = jsonArray
		} else {
			return nil, fmt.Errorf("[SingboxParser] Incorrect Json Format")
		}

		newContent, _ := json.MarshalIndent(jsonObj, "", "  ")

		return patchConfig(newContent, "SingboxParser", configOpt)
	}

	v2rayStr, err := ray2sing.Ray2Singbox(context.Background(), string(content), configOpt.UseXrayCoreWhenPossible)
	if err == nil {
		return patchConfig([]byte(v2rayStr), "V2rayParser", configOpt)
	}
	fmt.Printf("Convert using clash\n")
	clashObj := clash.Clash{}
	if err := yaml.Unmarshal(content, &clashObj); err == nil && clashObj.Proxies != nil {
		if len(clashObj.Proxies) == 0 {
			return nil, fmt.Errorf("[ClashParser] no outbounds found")
		}
		converted, err := convert.Clash2sing(clashObj)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] converting clash to sing-box error: %w", err)
		}
		output := configByte
		output, err = convert.Patch(output, converted, "", "", nil)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] patching clash config error: %w", err)
		}
		return patchConfig(output, "ClashParser", configOpt)
	}

	return nil, fmt.Errorf("unable to determine config format")
}

func patchConfig(content []byte, name string, configOpt *HiddifyOptions) ([]byte, error) {
	options, err := SJ.UnmarshalExtendedContext[option.Options](singboxContext(), content)
	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] unmarshal error: %w", err)
	}
	// A custom warp outbound converts into a WireGuard endpoint here; the
	// batch result carries either the patched outbound or the new endpoint.
	type patchWarpResult struct {
		outbound *option.Outbound
		endpoint *option.Endpoint
	}
	b, _ := batch.New(context.Background(), batch.WithConcurrencyNum[patchWarpResult](2))
	for _, base := range options.Outbounds {
		out := base
		b.Go(base.Tag, func() (patchWarpResult, error) {
			if ep, converted, err := warpOutboundToEndpoint(out, configOpt, false, nil); err != nil {
				return patchWarpResult{}, fmt.Errorf("[Warp] patch warp error: %w", err)
			} else if converted {
				return patchWarpResult{endpoint: ep}, nil
			}
			return patchWarpResult{outbound: &out}, nil
		})
	}
	if res, err := b.WaitAndGetResult(); err != nil {
		return nil, err
	} else {
		var outbounds []option.Outbound
		var endpoints []option.Endpoint
		for _, base := range options.Outbounds {
			result := res[base.Tag].Value
			if result.endpoint != nil {
				endpoints = append(endpoints, *result.endpoint)
			} else if result.outbound != nil {
				outbounds = append(outbounds, *result.outbound)
			}
		}
		options.Outbounds = outbounds
		options.Endpoints = append(options.Endpoints, endpoints...)
	}

	compact, err := SJ.MarshalContext(singboxContext(), options)
	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] marshal error: %w", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("[SingboxParser] marshal error: %w", err)
	}
	content = indented.Bytes()

	// fmt.Printf("%s\n", content)
	return validateResult(content, name)
}

func validateResult(content []byte, name string) ([]byte, error) {
	err := libbox.CheckConfig(string(content))
	if err != nil {
		return nil, fmt.Errorf("[%s] invalid sing-box config: %w", name, err)
	}
	return content, nil
}
