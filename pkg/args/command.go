package args

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/secrets"
	flag "github.com/spf13/pflag"
)

var _ Command = (*Cmd[interface{}])(nil)

var _ Command = (*ParentCommand)(nil)

type PositionalArg[V any] struct {
	Name        string
	Description string
	Multiple    bool
	Required    bool
	Parse       func(args []string, cfg *V) (next []string, err error)
}

type ParentCommand struct {
	Names            []string
	Description      string
	ShortDescription string
	SubCommands      []Command

	command Command
}

func (c *ParentCommand) SetFlags(flags *flag.FlagSet, args []string) []string {
	if len(args) > 0 {
		commandName := strings.ToLower(strings.TrimSpace(args[0]))
		for _, cmd := range c.SubCommands {
			for _, name := range cmd.Usage().Names {
				if name == commandName {
					c.command = cmd
					return cmd.SetFlags(flags, args[1:])
				}
			}
		}
	}
	return args
}

func (c *ParentCommand) Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, positionalArgs []string) error {
	if c.command != nil {
		return c.command.Call(ctx, log, cfg, positionalArgs)
	}
	c.Help(nil)
	return nil
}

func (c *ParentCommand) Help(err error) {

	if c.command != nil {
		c.command.Help(err)
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "USAGE: %s COMMAND", strings.Join(c.Names, ","))
	if c.Description != "" {
		_, _ = fmt.Fprintf(os.Stderr, "\n")
		_, _ = fmt.Fprintf(os.Stderr, "\n")
		_, _ = fmt.Fprint(os.Stderr, c.Description)
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Commands:\n")
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 1, ' ', tabwriter.AlignRight|tabwriter.Debug)
	for _, cmd := range c.SubCommands {
		usage := cmd.Usage()
		_, _ = fmt.Fprintln(w, strings.Join(usage.Names, ","), "\t", usage.Usage)
	}
	_ = w.Flush()

	var verbose bool
	var debug bool
	var QemuPath, CacheDir, ConfigDir, DataDir string
	globalFlags := newGlobalFlags(flag.NewFlagSet("", flag.ContinueOnError), &verbose, &debug, &QemuPath, &CacheDir, &ConfigDir, &DataDir)
	globalFlags.Usage = func() {}

	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Global Options:\n")
	_, _ = fmt.Fprintf(os.Stderr, "%s", globalFlags.FlagUsagesWrapped(0))

	if err != nil && !errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintf(os.Stderr, "\n")
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
}

func (c *ParentCommand) Usage() Usage {
	return Usage{
		Names: slices.Clone(c.Names),
		Usage: c.ShortDescription,
	}
}

type Cmd[V any] struct {
	Names            []string
	Description      string
	ShortDescription string
	Flags            func(cfg *V, flags *flag.FlagSet)
	PositionalArgs   []*PositionalArg[V]
	Run              func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *V) error

	cmdCfg *V
	ctx    context.Context
	log    *slog.Logger
}

func (c *Cmd[V]) SetFlags(flags *flag.FlagSet, args []string) []string {
	c.cmdCfg = new(V)
	c.Flags(c.cmdCfg, flags)
	return args
}

func (c *Cmd[V]) Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, positionalArgs []string) error {

	c.log = log
	c.ctx = ctx

	var err error
	for _, arg := range c.PositionalArgs {
		if len(positionalArgs) > 0 {
			positionalArgs, err = arg.Parse(positionalArgs, c.cmdCfg)
			if err != nil {
				break
			}
		}
	}
	if len(positionalArgs) > 0 && err == nil {
		err = fmt.Errorf("command takes no additional positional arguments")
	}
	if err != nil {
		c.Help(err)
		return err
	}
	if len(positionalArgs) > 0 && slices.ContainsFunc(c.PositionalArgs, func(p *PositionalArg[V]) bool {
		return p.Required
	}) {
		err = fmt.Errorf("missing required positional arguments")
		c.Help(err)
		return err
	}

	if err = secrets.EnsurePasswordFromConfig(ctx, cfg); err != nil {
		fmt.Println(err.Error())
		return err
	}

	return c.Run(c.ctx, c.log, cfg, c.cmdCfg)
}

func (c *Cmd[V]) Help(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "USAGE: %s", strings.Join(c.Names, ","))
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.Usage = func() {}
	c.SetFlags(flags, []string{})
	if flags.HasFlags() {
		_, _ = fmt.Fprintf(os.Stderr, " [OPTIONS]")
	}
	if len(c.PositionalArgs) > 0 {
		for _, cmd := range c.PositionalArgs {
			_, _ = fmt.Fprintf(os.Stderr, " ")
			if !cmd.Required {
				_, _ = fmt.Fprintf(os.Stderr, "[")
			}
			_, _ = fmt.Fprintf(os.Stderr, "%s", strings.ToUpper(cmd.Name))
			if !cmd.Required {
				_, _ = fmt.Fprintf(os.Stderr, "]")
			}
			if cmd.Multiple && cmd.Required {
				_, _ = fmt.Fprintf(os.Stderr, " [%s...]", strings.ToUpper(cmd.Name))
			}
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", c.Description)
	_, _ = fmt.Fprintf(os.Stderr, "\n")

	if len(c.PositionalArgs) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Arguments:\n")
		for _, cmd := range c.PositionalArgs {
			_, _ = fmt.Fprintf(os.Stderr, " %s: %s", strings.ToUpper(cmd.Name), cmd.Description)
			var modifiers []string
			if cmd.Multiple {
				modifiers = append(modifiers, "MULTIPLE")
			}
			if cmd.Required {
				modifiers = append(modifiers, "REQUIRED")
			}
			if len(modifiers) > 0 {
				_, _ = fmt.Fprintf(os.Stderr, " [%s]", strings.Join(modifiers, ","))
			}
			_, _ = fmt.Fprintf(os.Stderr, "\n")
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if flags.HasFlags() {
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		_, _ = fmt.Fprintf(os.Stderr, "%s", flags.FlagUsagesWrapped(0))
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	var verbose bool
	var debug bool
	var QemuPath, CacheDir, ConfigDir, DataDir string
	globalFlags := newGlobalFlags(flag.NewFlagSet("", flag.ContinueOnError), &verbose, &debug, &QemuPath, &CacheDir, &ConfigDir, &DataDir)
	globalFlags.Usage = func() {}

	_, _ = fmt.Fprintf(os.Stderr, "Global Options:\n")
	_, _ = fmt.Fprintf(os.Stderr, "%s", globalFlags.FlagUsagesWrapped(0))

	if err != nil && !errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintf(os.Stderr, "\n")
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
}

func (c *Cmd[V]) Usage() Usage {
	return Usage{
		Names: slices.Clone(c.Names),
		Usage: c.ShortDescription,
	}
}
