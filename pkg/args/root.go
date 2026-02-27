package args

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/Rudd3r/r0mp/pkg/domain"
	flag "github.com/spf13/pflag"
)

//var globalFlags *flag.FlagSet

func newGlobalFlags(g *flag.FlagSet, verbose, debug *bool, QemuPath, CacheDir, ConfigDir, DataDir *string) *flag.FlagSet {
	//g.BoolP("help", "h", false, "Show this help")
	g.BoolVar(verbose, "verbose", false, "Verbose output")
	g.BoolVar(debug, "debug", false, "Debug output")
	g.StringVar(QemuPath, "qemu-path", "", "Path to QEMU executable")
	g.StringVar(CacheDir, "cache-dir", "", "Path to cache directory")
	g.StringVar(ConfigDir, "config-dir", "", "Path to config dir")
	g.StringVar(DataDir, "data-dir", "", "Path to data dir")
	return g
}

type Command interface {
	SetFlags(flags *flag.FlagSet, args []string) []string
	Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, positionalArgs []string) error
	Usage() Usage
	Help(err error)
}

type Usage struct {
	Names []string
	Usage string
}

type Root struct {
	Commands []Command

	cfg *domain.Config
}

func (r *Root) Run(args []string) {

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

	var verbose bool
	var debug bool
	var QemuPath, CacheDir, ConfigDir, DataDir string
	globalFlags := newGlobalFlags(flag.NewFlagSet("", flag.ContinueOnError), &verbose, &debug, &QemuPath, &CacheDir, &ConfigDir, &DataDir)
	globalFlags.Usage = func() {}

	var command Command
	if len(args) > 1 {
		commandName := strings.ToLower(strings.TrimSpace(args[1]))
		for _, cmd := range r.Commands {
			for _, name := range cmd.Usage().Names {
				if name == commandName {
					args = cmd.SetFlags(globalFlags, args[2:])
					command = cmd
					break
				}
			}
		}
	}

	err := globalFlags.ParseAll(args, func(flag *flag.Flag, value string) error {
		return globalFlags.Set(flag.Name, value)
	})
	if err != nil {
		if command != nil {
			command.Help(err)
			exit = 2
			return
		}

		r.help(globalFlags, err)
		exit = 2
		return
	}

	r.cfg = &domain.Config{}
	cfgDir, err := getConfigDirectory(ConfigDir)
	if err != nil {
		fmt.Println(err.Error())
		exit = 1
		return
	}
	if err = r.cfg.Load(cfgDir); err != nil {
		fmt.Println(err.Error())
		exit = 1
		return
	}

	if debug {
		r.cfg.LogLevel = slog.LevelDebug
	} else if verbose {
		r.cfg.LogLevel = slog.LevelInfo
	}
	if QemuPath != "" {
		r.cfg.QemuPath = QemuPath
	}
	if ConfigDir != "" {
		r.cfg.ConfigDir = ConfigDir
	}
	if DataDir != "" {
		r.cfg.DataDir = DataDir
	}

	logCfg := &slog.HandlerOptions{Level: r.cfg.LogLevel}
	if r.cfg.LogLevel == slog.LevelDebug {
		logCfg.AddSource = true
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, logCfg))
	log.Debug("Created logger", "log_level", r.cfg.LogLevel)

	var positionalArgs []string
	if len(args) > 0 {
		i := slices.Index(args, globalFlags.Arg(0))
		if i >= 0 {
			positionalArgs = args[i:]
		}
	}

	if command != nil {
		if err := command.Call(ctx, log, r.cfg, positionalArgs); err != nil {
			exit = 1
		}
		return
	}

	r.help(globalFlags, nil)
}

func getConfigDirectory(dir string) (cfgDir string, err error) {
	if dir != "" {
		return dir, nil
	}
	cfgDir, _ = domain.UserConfigDir()
	if cfgDir == "" {
		return cfgDir, errors.New("cannot determine config directory")
	}
	return cfgDir, nil
}

func (r *Root) help(globalFlags *flag.FlagSet, err error) {
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

	if err != nil && !errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintf(os.Stderr, "\n")
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
}
