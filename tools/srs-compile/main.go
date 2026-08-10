package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("srs-compile", flag.ContinueOnError)
	outputPath := flags.String("output", "", "output .srs path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" {
		return errors.New("--output is required")
	}
	if flags.NArg() != 1 {
		return errors.New("exactly one source JSON path is required")
	}
	return compileRuleSet(flags.Arg(0), *outputPath)
}

func compileRuleSet(sourcePath string, outputPath string) error {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read source rule set: %w", err)
	}
	plainRuleSet, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
	if err != nil {
		return fmt.Errorf("parse source rule set: %w", err)
	}

	var output bytes.Buffer
	err = srs.Write(&output, plainRuleSet.Options, downgradeRuleSetVersion(plainRuleSet.Version, plainRuleSet.Options))
	if err != nil {
		return fmt.Errorf("compile rule set: %w", err)
	}
	if err := os.WriteFile(outputPath, output.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write compiled rule set: %w", err)
	}
	return nil
}

// downgradeRuleSetVersion mirrors the sing-box compiler's compatibility behavior.
func downgradeRuleSetVersion(version uint8, ruleSet option.PlainRuleSet) uint8 {
	if version == C.RuleSetVersion4 && !hasHeadlessRule(ruleSet.Rules, func(rule option.DefaultHeadlessRule) bool {
		return rule.NetworkInterfaceAddress != nil && rule.NetworkInterfaceAddress.Size() > 0 ||
			len(rule.DefaultInterfaceAddress) > 0
	}) {
		version = C.RuleSetVersion3
	}
	if version == C.RuleSetVersion3 && !hasHeadlessRule(ruleSet.Rules, func(rule option.DefaultHeadlessRule) bool {
		return len(rule.NetworkType) > 0 || rule.NetworkIsExpensive || rule.NetworkIsConstrained
	}) {
		version = C.RuleSetVersion2
	}
	return version
}

func hasHeadlessRule(rules []option.HeadlessRule, condition func(rule option.DefaultHeadlessRule) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			if condition(rule.DefaultOptions) {
				return true
			}
		case C.RuleTypeLogical:
			if hasHeadlessRule(rule.LogicalOptions.Rules, condition) {
				return true
			}
		}
	}
	return false
}
