package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Xarth-Mai/Attachment-Gate/internal/app"
)

// version is intentionally committed so downstream release manifests can pin
// the exact Attachment Gate contract. Release builds may still override it
// with -ldflags "-X main.version=...".
var version = "0.1.6"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: attachment-gate <scan|doctor|policy|version>")
		return app.ExitUsage
	}
	var err error
	switch args[0] {
	case "scan":
		flags := flag.NewFlagSet("scan", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		input := flags.String("input", "", "input batch directory")
		output := flags.String("output", "", "result directory")
		configPath := flags.String("config", "", "configuration file")
		verbose := flags.Bool("verbose", false, "write scan details to stderr")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *input == "" || *output == "" || *configPath == "" {
			_, _ = fmt.Fprintln(stderr, "usage: attachment-gate scan --input DIR --output DIR --config FILE [--verbose]")
			return app.ExitUsage
		}
		var log io.Writer
		if *verbose {
			log = stderr
		}
		err = app.Scan(ctx, app.ScanOptions{Input: *input, Output: *output, ConfigPath: *configPath, Verbose: log})
	case "doctor":
		flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		configPath := flags.String("config", "", "configuration file")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *configPath == "" {
			_, _ = fmt.Fprintln(stderr, "usage: attachment-gate doctor --config FILE")
			return app.ExitUsage
		}
		err = app.Doctor(ctx, *configPath)
	case "policy":
		flags := flag.NewFlagSet("policy", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		configPath := flags.String("config", "", "configuration file")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *configPath == "" {
			_, _ = fmt.Fprintln(stderr, "usage: attachment-gate policy --config FILE")
			return app.ExitUsage
		}
		identity, identityErr := app.DescribePolicy(*configPath, version)
		if identityErr != nil {
			err = identityErr
		} else {
			err = json.NewEncoder(stdout).Encode(identity)
		}
	case "version":
		if len(args) != 1 {
			return app.ExitUsage
		}
		_, _ = fmt.Fprintf(stdout, "attachment-gate %s\n", version)
		return app.ExitOK
	default:
		_, _ = fmt.Fprintln(stderr, "usage: attachment-gate <scan|doctor|policy|version>")
		return app.ExitUsage
	}
	if err == nil {
		return app.ExitOK
	}
	_, _ = fmt.Fprintln(stderr, strings.Join(strings.Fields(err.Error()), " "))
	var exit *app.ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return app.ExitInternal
}
