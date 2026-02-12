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
}

func (c *ParentCommand) Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, args []string) error {
	if len(args) > 0 {
		commandName := strings.ToLower(strings.TrimSpace(args[0]))
		for _, cmd := range c.SubCommands {
			for _, name := range cmd.Usage().Names {
				if name == commandName {
					return cmd.Call(ctx, log, cfg, args[1:])
				}
			}
		}
	}
	c.help()
	return nil
}

func (c *ParentCommand) help() {
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
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "Global Options:\n")
	_, _ = fmt.Fprintf(os.Stderr, "%s", globalFlags.FlagUsagesWrapped(0))
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
	flags  *flag.FlagSet
	ctx    context.Context
	log    *slog.Logger
}

func (c *Cmd[V]) Call(ctx context.Context, log *slog.Logger, cfg *domain.Config, args []string) error {

	c.flags = flag.NewFlagSet("", flag.ContinueOnError)
	c.log = log
	c.ctx = ctx
	c.cmdCfg = new(V)
	c.Flags(c.cmdCfg, c.flags)
	c.flags.Init("", flag.ContinueOnError)
	c.flags.Usage = func() {}
	if err := c.flags.Parse(args); err != nil {
		c.help(err)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var positionalArgs []string
	if len(args) > 0 {
		i := slices.Index(args, c.flags.Arg(0))
		if i >= 0 {
			positionalArgs = args[i:]
		}
	}

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
		c.help(err)
		return err
	}
	if len(positionalArgs) > 0 && slices.ContainsFunc(c.PositionalArgs, func(p *PositionalArg[V]) bool {
		return p.Required
	}) {
		err = fmt.Errorf("missing required positional arguments")
		c.help(err)
		return err
	}

	if err = secrets.EnsurePasswordFromConfig(ctx, cfg); err != nil {
		fmt.Println(err.Error())
		return err
	}

	return c.Run(c.ctx, c.log, cfg, c.cmdCfg)
}

func (c *Cmd[V]) help(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "USAGE: %s", strings.Join(c.Names, ","))
	if c.flags.HasFlags() {
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

	if c.flags.HasFlags() {
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		_, _ = fmt.Fprintf(os.Stderr, "%s", c.flags.FlagUsagesWrapped(0))
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}
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
