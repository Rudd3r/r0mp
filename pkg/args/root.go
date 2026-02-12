package args

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/Rudd3r/r0mp/pkg/domain"
	flag "github.com/spf13/pflag"
)

var globalFlags *flag.FlagSet

type Command interface {
	Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, args []string) error
	Usage() Usage
}

type Usage struct {
	Names []string
	Usage string
}

type Root struct {
	Commands []Command

	cfg *domain.Config
}

func (r *Root) Run() {

	var exit int
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		if rcv := recover(); rcv != nil {
			panic(rcv)
		}
		os.Exit(exit)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	cfgDir, err := getConfigDirectory()
	if err != nil {
		fmt.Println(err.Error())
		exit = 1
		return
	}

	r.cfg = &domain.Config{}
	if err = r.cfg.Load(cfgDir); err != nil {
		fmt.Println(err.Error())
		exit = 1
		return
	}
	r.handleGlobalFlags()

	logCfg := &slog.HandlerOptions{Level: r.cfg.LogLevel}
	if r.cfg.LogLevel == slog.LevelDebug {
		logCfg.AddSource = true
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, logCfg))

	if len(os.Args) > 1 {
		commandName := strings.ToLower(strings.TrimSpace(os.Args[1]))
		for _, cmd := range r.Commands {
			for _, name := range cmd.Usage().Names {
				if name == commandName {
					if err := cmd.Call(ctx, log, r.cfg, os.Args[2:]); err != nil {
						exit = 1
					}
					return
				}
			}
		}
	}

	r.help()
}

func (r *Root) handleGlobalFlags() {
	var verbose bool
	var debug bool

	globalFlags = flag.NewFlagSet("global", flag.ContinueOnError)
	globalFlags.BoolP("help", "h", false, "Show this help")
	globalFlags.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	globalFlags.BoolVar(&debug, "debug", false, "Debug output")
	globalFlags.StringVar(&r.cfg.QemuPath, "qemu-path", r.cfg.QemuPath, "Path to QEMU executable")
	globalFlags.StringVar(&r.cfg.CacheDir, "cache-dir", r.cfg.CacheDir, "Path to cache directory")
	globalFlags.StringVar(&r.cfg.ConfigDir, "config-dir", r.cfg.ConfigDir, "Path to config dir")
	globalFlags.StringVar(&r.cfg.DataDir, "data-dir", r.cfg.DataDir, "Path to data dir")
	_ = globalFlags.ParseAll(os.Args, func(flag *flag.Flag, value string) error {
		_ = globalFlags.Set(flag.Name, value)
		return nil
	})

	if verbose {
		r.cfg.LogLevel = slog.LevelInfo
	}
	if debug {
		r.cfg.LogLevel = slog.LevelDebug
	}
}

func getConfigDirectory() (cfgDir string, err error) {
	cfgDir, _ = domain.UserConfigDir()
	f := flag.NewFlagSet("", flag.ContinueOnError)
	f.BoolP("help", "h", false, "Show this help")
	f.StringVar(&cfgDir, "config_dir", cfgDir, "Path to config dir")
	_ = f.ParseAll(os.Args, func(flag *flag.Flag, value string) error {
		_ = f.Set(flag.Name, value)
		return nil
	})
	if cfgDir == "" {
		return cfgDir, errors.New("cannot determine config directory")
	}
	return cfgDir, nil
}

func (r *Root) help() {
	_, _ = fmt.Fprintf(os.Stderr, "USAGE: %s [OPTIONS] COMMAND\n", os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Ephemeral VM playground\n")
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Commands:\n")
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 1, ' ', tabwriter.AlignRight|tabwriter.Debug)
	for _, cmd := range r.Commands {
		usage := cmd.Usage()
		_, _ = fmt.Fprintln(w, strings.Join(usage.Names, ","), "\t", usage.Usage)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Global Options:\n")
	_, _ = fmt.Fprintf(os.Stderr, "%s", globalFlags.FlagUsagesWrapped(0))
}
