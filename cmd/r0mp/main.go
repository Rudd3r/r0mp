package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/Rudd3r/r0mp/pkg/args"
	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/Rudd3r/r0mp/pkg/image"
	"github.com/Rudd3r/r0mp/pkg/policy"
	"github.com/Rudd3r/r0mp/pkg/r0mp"
	"github.com/Rudd3r/r0mp/pkg/secrets"

	flag "github.com/spf13/pflag"
)

func main() {
	(&args.Root{
		Commands: []args.Command{
			&args.Cmd[domain.CommandRun]{
				Names:            []string{"run"},
				Description:      "Run a raft",
				ShortDescription: "Run a raft",
				PositionalArgs:   []*args.PositionalArg[domain.CommandRun]{},
				Flags: func(cfg *domain.CommandRun, flags *flag.FlagSet) {
					flags.StringVarP(
						&cfg.Name,
						"name", "n", "",
						"Name of the raft",
					)
					flags.StringVarP(
						&cfg.Image,
						"image", "i", domain.DefaultImage,
						"Image to use",
					)
					flags.UintVarP(
						&cfg.CPU,
						"cpu", "c", domain.DefaultCpuCount,
						"Number of CPUs",
					)
					flags.StringVarP(
						&cfg.Memory,
						"memory", "m", domain.DefaultMemorySize,
						"Memory allocation",
					)
					flags.StringVar(
						&cfg.Policy,
						"policy", "",
						"Policy to use",
					)
					flags.VarP(
						args.NewDiskBytes(domain.DefaultVolumeSizeBytes, &cfg.VolumeSizeBytes),
						"disk", "d",
						"Disk size in bytes. If an image is specified, and disk size unset, disk size will be "+
							"image size plus default disk size.",
					)
					flags.StringArrayVarP(
						&cfg.Volumes,
						"volume", "v", nil,
						"Volume mount in the format HOST_PATH:GUEST_PATH[:ro] (e.g., /tmp:/data or /tmp:/data:ro for read-only)",
					)
					flags.VarP(
						args.NewPortsValue(&cfg.Ports),
						"publish", "p",
						"Publish a port to the host (format: host_port:guest_port or host_ip:host_port:guest_port)",
					)
					flags.Var(
						args.NewIngressProxyPortsValue(&cfg.IngressProxyPorts),
						"ingress",
						"Configure ingress proxy port (format: [policy@][scheme://][hostip:]hostport-guestport, e.g., 8080-80, mypolicy@https://8443-443)",
					)
					flags.FuncP("env", "e", "Set environment variable", func(s string) error {
						split := strings.SplitN(s, "=", 2)
						if len(split) != 2 {
							return fmt.Errorf("invalid environment variable: %s", s)
						}
						if cfg.Environment == nil {
							cfg.Environment = make(map[string]string)
						}
						cfg.Environment[split[0]] = split[1]
						return nil
					})
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandRun) error {
					resetIfDefault(&cmdCfg.CPU, domain.DefaultCpuCount)
					resetIfDefault(&cmdCfg.Memory, domain.DefaultMemorySize)
					resetIfDefault(&cmdCfg.VolumeSizeBytes, domain.DefaultVolumeSizeBytes)

					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Run(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandStart]{
				Names:            []string{"start"},
				Description:      "Start a raft",
				ShortDescription: "Start a raft",
				PositionalArgs:   []*args.PositionalArg[domain.CommandStart]{},
				Flags: func(cfg *domain.CommandStart, flags *flag.FlagSet) {
					flags.StringVarP(
						&cfg.Name,
						"name", "n", "",
						"Name of the raft",
					)
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandStart) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Run(&domain.CommandRun{Name: cmdCfg.Name}); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.ParentCommand{
				Names:            []string{"policy"},
				Description:      "Raft policies",
				ShortDescription: "Raft policies",
				SubCommands: []args.Command{
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"new"},
						Description:      "Create a new policy",
						ShortDescription: "Create a new policy",
						Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "Name",
								Description: "Policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.PolicyName = args[0]
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							builder := newPolicyBuilder(cfg)
							pol, err := builder.New(cmdCfg.PolicyName)
							if err != nil {
								return fmt.Errorf("failed to create policy: %w", err)
							}
							fmt.Printf("Created policy: %s\n", pol.Name)
							return nil
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"ls", "list"},
						Description:      "List policies",
						ShortDescription: "List policies",
						Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
						PositionalArgs:   []*args.PositionalArg[domain.CommandPolicy]{},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							builder := newPolicyBuilder(cfg)
							policies, err := builder.List()
							if err != nil {
								return fmt.Errorf("failed to list policies: %w", err)
							}

							if len(policies) == 0 {
								fmt.Println("No policies found")
								return nil
							}

							w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
							_, _ = fmt.Fprintln(w, "NAME\tALLOWED RULES\tDENIED RULES\t")
							for _, pol := range policies {
								_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t\n", pol.Name, len(pol.AcceptRules), len(pol.DenyRules))
							}
							_ = w.Flush()
							return nil
						},
					},
					&args.ParentCommand{
						Names:            []string{"rm", "remove"},
						Description:      "Remove a policy or rule",
						ShortDescription: "Remove a policy or rule",
						SubCommands: []args.Command{
							&args.Cmd[domain.CommandPolicy]{
								Names:            []string{"policy"},
								Description:      "Remove policy",
								ShortDescription: "Remove policy",
								Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
								PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
									{
										Name:        "Name",
										Description: "Policy name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.PolicyName = args[0]
											return args[1:], nil
										},
									},
								},
								Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
									builder := newPolicyBuilder(cfg)
									err := builder.Remove(cmdCfg.PolicyName)
									if err != nil {
										return fmt.Errorf("failed to remove policy: %w", err)
									}
									fmt.Printf("Removed policy: %s\n", cmdCfg.PolicyName)
									return nil
								},
							},
							&args.Cmd[domain.CommandPolicy]{
								Names:            []string{"rule"},
								Description:      "Remove rule from policy",
								ShortDescription: "Remove rule from policy",
								Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
								PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
									{
										Name:        "PolicyName",
										Description: "Policy name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.PolicyName = args[0]
											return args[1:], nil
										},
									},
									{
										Name:        "RuleName",
										Description: "Rule name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.RuleName = args[0]
											return args[1:], nil
										},
									},
								},
								Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
									builder := newPolicyBuilder(cfg)
									_, err := builder.RemoveRule(cmdCfg.PolicyName, cmdCfg.RuleName)
									if err != nil {
										return fmt.Errorf("failed to remove rule: %w", err)
									}
									fmt.Printf("Removed rule %s from policy %s\n", cmdCfg.RuleName, cmdCfg.PolicyName)
									return nil
								},
							},
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"merge"},
						Description:      "Merge source policy into target policy",
						ShortDescription: "Merge policies",
						Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "Source",
								Description: "Source policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.Source = args[0]
									return args[1:], nil
								},
							},
							{
								Name:        "Target",
								Description: "Target policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.Target = args[0]
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							builder := newPolicyBuilder(cfg)
							pol, err := builder.Merge(cmdCfg.Source, cmdCfg.Target)
							if err != nil {
								return fmt.Errorf("failed to merge policies: %w", err)
							}
							fmt.Printf("Merged policy %s into %s (now has %d allowed rules, %d denied rules)\n",
								cmdCfg.Source, cmdCfg.Target, len(pol.AcceptRules), len(pol.DenyRules))
							return nil
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"move"},
						Description:      "Move a rule to a specific position",
						ShortDescription: "Move rule",
						Flags: func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {
							// No flags for move command
						},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "PolicyName",
								Description: "Policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.PolicyName = args[0]
									return args[1:], nil
								},
							},
							{
								Name:        "RuleName",
								Description: "Rule name to move",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.RuleName = args[0]
									return args[1:], nil
								},
							},
							{
								Name:        "Position",
								Description: "New position (0-indexed)",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									pos, err := strconv.Atoi(args[0])
									if err != nil {
										return nil, fmt.Errorf("position must be a number: %w", err)
									}
									cfg.Position = pos
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							builder := newPolicyBuilder(cfg)
							pol, err := builder.MoveRule(cmdCfg.PolicyName, cmdCfg.RuleName, cmdCfg.Position)
							if err != nil {
								return fmt.Errorf("failed to move rule: %w", err)
							}
							fmt.Printf("Moved rule '%s' to position %d in policy %s\n",
								cmdCfg.RuleName, cmdCfg.Position, cmdCfg.PolicyName)

							// Show the new order
							fmt.Println("\nCurrent rule order:")
							if len(pol.AcceptRules) > 0 {
								fmt.Println("  AcceptRules rules:")
								for i, rule := range pol.AcceptRules {
									fmt.Printf("    %d. %s\n", i, rule.Name)
								}
							}
							if len(pol.DenyRules) > 0 {
								fmt.Println("  DenyRules rules:")
								for i, rule := range pol.DenyRules {
									fmt.Printf("    %d. %s\n", i, rule.Name)
								}
							}
							return nil
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"allow"},
						Description:      "Add allow rule to policy",
						ShortDescription: "Add allow rule",
						Flags: func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {
							flags.StringArrayVar(&cfg.Domain, "domain", nil, "Domain pattern to match (required)")
							flags.StringArrayVar(&cfg.Path, "path", nil, "Path pattern(s) to allow (repeatable)")
							flags.StringArrayVar(&cfg.Schemes, "scheme", nil, "Scheme(s) to allow: http or https (repeatable)")
							flags.StringArrayVar(&cfg.Method, "method", nil, "HTTP method(s) to allow (repeatable)")
						},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "PolicyName",
								Description: "Policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.PolicyName = args[0]
									return args[1:], nil
								},
							},
							{
								Name:        "RuleName",
								Description: "Rule name (friendly identifier)",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.RuleName = args[0]
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							if len(cmdCfg.Domain) == 0 {
								return fmt.Errorf("--domain flag is required")
							}

							builder := newPolicyBuilder(cfg)

							_, err := builder.Allow(cmdCfg.PolicyName, cmdCfg.RuleName, cmdCfg.Domain, cmdCfg.Method, cmdCfg.Path, cmdCfg.Schemes)
							if err != nil {
								return fmt.Errorf("failed to add allow rule: %w", err)
							}
							fmt.Printf("Added allow rule '%s' (matching %v) to policy %s\n",
								cmdCfg.RuleName, cmdCfg.Domain, cmdCfg.PolicyName)
							return nil
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"deny"},
						Description:      "Add deny rule to policy",
						ShortDescription: "Add deny rule",
						Flags: func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {
							flags.StringArrayVar(&cfg.Domain, "domain", nil, "Domain pattern to match (required)")
							flags.StringArrayVar(&cfg.Path, "path", nil, "Path pattern(s) to deny (repeatable)")
							flags.StringArrayVar(&cfg.Schemes, "scheme", nil, "Scheme(s) to deny: http or https (repeatable)")
							flags.StringArrayVar(&cfg.Method, "method", nil, "HTTP method(s) to deny (repeatable)")
						},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "PolicyName",
								Description: "Policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.PolicyName = args[0]
									return args[1:], nil
								},
							},
							{
								Name:        "RuleName",
								Description: "Rule name (friendly identifier)",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.RuleName = args[0]
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							if len(cmdCfg.Domain) == 0 {
								return fmt.Errorf("--domain flag is required")
							}

							builder := newPolicyBuilder(cfg)

							_, err := builder.Deny(cmdCfg.PolicyName, cmdCfg.RuleName, cmdCfg.Domain, cmdCfg.Method, cmdCfg.Path, cmdCfg.Schemes)
							if err != nil {
								return fmt.Errorf("failed to add deny rule: %w", err)
							}
							fmt.Printf("Added deny rule '%s' (matching %v) to policy %s\n",
								cmdCfg.RuleName, cmdCfg.Domain, cmdCfg.PolicyName)
							return nil
						},
					},
					&args.ParentCommand{
						Names:            []string{"auth"},
						Description:      "Manage authentication for policy rules",
						ShortDescription: "Manage authentication",
						SubCommands: []args.Command{
							&args.Cmd[domain.CommandPolicy]{
								Names:            []string{"add"},
								Description:      "Add authentication to a policy rule",
								ShortDescription: "Add authentication",
								Flags: func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {
									flags.StringVar(&cfg.Type, "type", "", "Auth type: bearer or basic (required)")
									flags.StringArrayVar(&cfg.Domain, "domain", nil, "Domain for auth (required)")
								},
								PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
									{
										Name:        "PolicyName",
										Description: "Policy name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.PolicyName = args[0]
											return args[1:], nil
										},
									},
									{
										Name:        "RuleName",
										Description: "Rule name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.RuleName = args[0]
											return args[1:], nil
										},
									},
								},
								Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
									if cmdCfg.Type == "" {
										return fmt.Errorf("--type flag is required (bearer or basic)")
									}

									builder := newPolicyBuilder(cfg)

									// Prompt for credentials
									var username, secret string
									if cmdCfg.Type == "basic" {
										fmt.Print("Enter username: ")
										_, _ = fmt.Scanln(&username)
									}
									fmt.Print("Enter secret/token: ")
									_, _ = fmt.Scanln(&secret)

									_, err := builder.Auth(cmdCfg.PolicyName, cmdCfg.Type, cmdCfg.RuleName, username, secret)
									if err != nil {
										return fmt.Errorf("failed to add auth: %w", err)
									}
									fmt.Printf("Added %s auth to rule %s in policy %s\n",
										cmdCfg.Type, cmdCfg.RuleName, cmdCfg.PolicyName)
									return nil
								},
							},
							&args.Cmd[domain.CommandPolicy]{
								Names:            []string{"rm", "remove"},
								Description:      "Remove authentication from a policy rule",
								ShortDescription: "Remove authentication",
								Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
								PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
									{
										Name:        "PolicyName",
										Description: "Policy name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.PolicyName = args[0]
											return args[1:], nil
										},
									},
									{
										Name:        "RuleName",
										Description: "Rule name",
										Required:    true,
										Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
											cfg.RuleName = args[0]
											return args[1:], nil
										},
									},
								},
								Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
									builder := newPolicyBuilder(cfg)
									_, err := builder.RemoveAuth(cmdCfg.PolicyName, cmdCfg.RuleName)
									if err != nil {
										return fmt.Errorf("failed to remove auth: %w", err)
									}
									fmt.Printf("Removed auth from rule %s in policy %s\n",
										cmdCfg.RuleName, cmdCfg.PolicyName)
									return nil
								},
							},
						},
					},
					&args.Cmd[domain.CommandPolicy]{
						Names:            []string{"show"},
						Description:      "Show policy details",
						ShortDescription: "Show policy",
						Flags:            func(cfg *domain.CommandPolicy, flags *flag.FlagSet) {},
						PositionalArgs: []*args.PositionalArg[domain.CommandPolicy]{
							{
								Name:        "PolicyName",
								Description: "Policy name",
								Required:    true,
								Parse: func(args []string, cfg *domain.CommandPolicy) (next []string, err error) {
									cfg.PolicyName = args[0]
									return args[1:], nil
								},
							},
						},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandPolicy) error {
							builder := newPolicyBuilder(cfg)
							pol, err := builder.Show(cmdCfg.PolicyName)
							if err != nil {
								return fmt.Errorf("failed to get policy: %w", err)
							}

							data, err := json.MarshalIndent(pol, "", "  ")
							if err != nil {
								return fmt.Errorf("failed to marshal policy: %w", err)
							}
							fmt.Println(string(data))
							return nil
						},
					},
				},
			},
			&args.ParentCommand{
				Names:            []string{"setup"},
				Description:      "Raft setup",
				ShortDescription: "Raft setup",
				SubCommands: []args.Command{
					&args.Cmd[domain.CommandSetupSecrets]{
						Names:            []string{"secrets"},
						Description:      "Interactive setup for secret store password",
						ShortDescription: "Setup secret store password",
						Flags:            func(cfg *domain.CommandSetupSecrets, flags *flag.FlagSet) {},
						PositionalArgs:   []*args.PositionalArg[domain.CommandSetupSecrets]{},
						Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandSetupSecrets) error {
							if err := secrets.SetupSecretStorePassword(ctx, cfg); err != nil {
								return fmt.Errorf("setup failed: %w", err)
							}
							fmt.Println()
							fmt.Println("✅ Setup completed successfully!")
							fmt.Println()
							return nil
						},
					},
				},
			},
			&args.Cmd[domain.CommandExec]{
				Names:            []string{"exec"},
				Description:      "Run command in raft",
				ShortDescription: "Run command in raft",
				Flags: func(cfg *domain.CommandExec, flags *flag.FlagSet) {
					flags.ParseErrorsAllowlist = flag.ParseErrorsAllowlist{UnknownFlags: true}
					flags.BoolVarP(&cfg.EnableTTY, "tty", "t", false, "Enable tty")
					flags.BoolVarP(&cfg.Interactive, "interactive", "i", false, "Interactive mode")
					flags.BoolVarP(&cfg.NoChroot, "no-chroot", "", false, "Disable chroot")
					flags.BoolVarP(&cfg.Detach, "detach", "d", false, "Run command in background")
					flags.FuncP("env", "e", "Set environment variable", func(s string) error {
						split := strings.SplitN(s, "=", 2)
						if len(split) != 2 {
							return fmt.Errorf("invalid environment variable: %s", s)
						}
						if cfg.Environment == nil {
							cfg.Environment = make(map[string]string)
						}
						cfg.Environment[split[0]] = split[1]
						return nil
					})
				},
				PositionalArgs: []*args.PositionalArg[domain.CommandExec]{
					{
						Name:        "Raft",
						Description: "Raft name or id",
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandExec) (next []string, err error) {
							cfg.Name = args[0]
							return args[1:], nil
						},
					},
					{
						Name:        "Command",
						Description: "Command",
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandExec) (next []string, err error) {
							cfg.Command = args[0]
							return args[1:], nil
						},
					},
					{
						Name:        "Args",
						Description: "Command args",
						Multiple:    true,
						Parse: func(args []string, cfg *domain.CommandExec) (next []string, err error) {
							cfg.Args = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandExec) error {
					// Validate flag combinations
					if cmdCfg.Detach && cmdCfg.Interactive {
						return fmt.Errorf("cannot use --detach with --interactive")
					}
					if cmdCfg.Detach && cmdCfg.EnableTTY {
						return fmt.Errorf("cannot use --detach with --tty")
					}

					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					err = cove.Exec(cmdCfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandList]{
				Names:            []string{"list", "ls"},
				Description:      "List rafts",
				ShortDescription: "List rafts",
				Flags:            func(cfg *domain.CommandList, flags *flag.FlagSet) {},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandList) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					listing, err := cove.List(cmdCfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}

					if len(listing) == 0 {
						fmt.Println("No rafts found")
						return nil
					}

					w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
					_, _ = fmt.Fprintln(w, "ID\tNAME\tIMAGE\tSTATUS\tCREATED")
					for _, raft := range listing {
						created := raft.Created.Format("2006-01-02 15:04:05")
						status := domain.FormatStatus(raft.State, raft.Started, raft.Stopped)
						_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
							raft.RaftID,
							raft.Name,
							raft.Image,
							status,
							created)
					}
					_ = w.Flush()
					return nil
				},
			},
			&args.Cmd[domain.CommandRemove]{
				Names:            []string{"remove", "rm"},
				Description:      "Remove rafts",
				ShortDescription: "Remove rafts",
				Flags:            func(cfg *domain.CommandRemove, flags *flag.FlagSet) {},
				PositionalArgs: []*args.PositionalArg[domain.CommandRemove]{
					{
						Name:        "Raft",
						Description: "Raft name or id",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandRemove) (next []string, err error) {
							cfg.Names = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandRemove) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Remove(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandStop]{
				Names:            []string{"stop"},
				Description:      "Stop running rafts by sending SIGTERM",
				ShortDescription: "Stop running rafts",
				Flags:            func(cfg *domain.CommandStop, flags *flag.FlagSet) {},
				PositionalArgs: []*args.PositionalArg[domain.CommandStop]{
					{
						Name:        "Raft",
						Description: "Raft name or id",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandStop) (next []string, err error) {
							cfg.Names = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandStop) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Stop(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandKill]{
				Names:            []string{"kill"},
				Description:      "Kill running rafts by sending SIGKILL",
				ShortDescription: "Kill running rafts",
				Flags:            func(cfg *domain.CommandKill, flags *flag.FlagSet) {},
				PositionalArgs: []*args.PositionalArg[domain.CommandKill]{
					{
						Name:        "Raft",
						Description: "Raft name or id",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandKill) (next []string, err error) {
							cfg.Names = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandKill) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Kill(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandCopy]{
				Names:            []string{"copy", "cp"},
				Description:      "Copy files/directories to/from raft. Use RAFT:PATH for raft paths.",
				ShortDescription: "Copy files to/from raft",
				Flags: func(cfg *domain.CommandCopy, flags *flag.FlagSet) {
					flags.BoolVarP(&cfg.NoChroot, "no-chroot", "", false, "Disable chroot")
				},
				PositionalArgs: []*args.PositionalArg[domain.CommandCopy]{
					{
						Name:        "Source",
						Description: "Source path (use RAFT:PATH for raft paths)",
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandCopy) (next []string, err error) {
							cfg.Source = args[0]
							return args[1:], nil
						},
					},
					{
						Name:        "Destination",
						Description: "Destination path (use RAFT:PATH for raft paths)",
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandCopy) (next []string, err error) {
							cfg.Destination = args[0]
							return args[1:], nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandCopy) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.Copy(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandGet]{
				Names:            []string{"get"},
				Description:      "Get raft info",
				ShortDescription: "Get raft info",
				Flags:            func(cfg *domain.CommandGet, flags *flag.FlagSet) {},
				PositionalArgs: []*args.PositionalArg[domain.CommandGet]{
					{
						Name:        "Raft",
						Description: "Raft name or id",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandGet) (next []string, err error) {
							cfg.Names = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandGet) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					listing, err := cove.Get(cmdCfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}

					if len(listing) == 0 {
						fmt.Println("No rafts found")
						return nil
					}

					jsBytes, _ := json.MarshalIndent(listing, "", "  ")
					fmt.Println(string(jsBytes))
					return nil
				},
			},
			&args.Cmd[domain.CommandImagesList]{
				Names:            []string{"images"},
				Description:      "List cached images",
				ShortDescription: "List cached images",
				Flags:            func(cfg *domain.CommandImagesList, flags *flag.FlagSet) {},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandImagesList) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					images, err := cove.ImagesList(cmdCfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if len(images) == 0 {
						fmt.Println("No cached images found")
						return nil
					}

					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					_, _ = fmt.Fprintln(w, "REF\tDIGEST\tLAYERS\tSIZE\tCACHED AT\t")
					for _, img := range images {
						sizeStr := domain.FormatSizeBytes(img.Size)
						digestShort := img.Digest
						if len(digestShort) > 19 {
							digestShort = digestShort[:19] + "..."
						}
						cachedAt := img.CachedAt.Format("2006-01-02 15:04:05")
						_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t\n", img.Reference, digestShort, len(img.LayerDigests), sizeStr, cachedAt)
					}
					_ = w.Flush()
					return nil
				},
			},
			&args.Cmd[domain.CommandImagesRemove]{
				Names:            []string{"rmi"},
				Description:      "Remove cached images",
				ShortDescription: "Remove cached images",
				Flags:            func(cfg *domain.CommandImagesRemove, flags *flag.FlagSet) {},
				PositionalArgs: []*args.PositionalArg[domain.CommandImagesRemove]{
					{
						Name:        "Image",
						Description: "Image reference",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandImagesRemove) (next []string, err error) {
							cfg.References = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandImagesRemove) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.ImagesRemove(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandImagesImport]{
				Names:            []string{"import"},
				Description:      "Import image(s) from a docker tar archive (created with `docker save`). Reads from stdin if no file is specified or if file is '-'.",
				ShortDescription: "Import images from tar",
				Flags: func(cfg *domain.CommandImagesImport, flags *flag.FlagSet) {
					flags.StringVarP(
						&cfg.Reference,
						"tag", "t", "",
						"Tag to assign to the imported image (required unless --all is used)",
					)
					flags.BoolVarP(
						&cfg.All,
						"all", "a", false,
						"Import all images from the tar file with their original tags",
					)
				},
				PositionalArgs: []*args.PositionalArg[domain.CommandImagesImport]{
					{
						Name:        "TarFile",
						Description: "Path to tar file (use '-' or omit for stdin)",
						Required:    false,
						Parse: func(args []string, cfg *domain.CommandImagesImport) (next []string, err error) {
							if len(args) > 0 {
								cfg.TarPath = args[0]
								return args[1:], nil
							}
							// Default to stdin if no argument provided
							cfg.TarPath = "-"
							return args, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandImagesImport) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if err = cove.ImagesImport(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
			&args.Cmd[domain.CommandMCP]{
				Names:            []string{"mcp"},
				Description:      "Start an MCP server that provides exec access to specified running rafts",
				ShortDescription: "Start MCP server for raft access",
				Flags: func(cfg *domain.CommandMCP, flags *flag.FlagSet) {
					flags.StringVar(&cfg.Host, "host", "127.0.0.1", "Host to bind the MCP server to")
					flags.StringVar(&cfg.Port, "port", "8080", "Port to bind the MCP server to")
					flags.BoolVar(&cfg.StdIO, "stdio", false, "Use stdio transport instead of HTTP")
				},
				PositionalArgs: []*args.PositionalArg[domain.CommandMCP]{
					{
						Name:        "Rafts",
						Description: "Names of running rafts to allow exec access to",
						Multiple:    true,
						Required:    true,
						Parse: func(args []string, cfg *domain.CommandMCP) (next []string, err error) {
							cfg.Names = slices.Clone(args)
							return nil, nil
						},
					},
				},
				Run: func(ctx context.Context, log *slog.Logger, cfg *domain.Config, cmdCfg *domain.CommandMCP) error {
					cove, err := newCove(ctx, log, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					if cmdCfg.StdIO {
						fmt.Printf("Starting MCP server with stdio transport for rafts: %v\n", cmdCfg.Names)
					} else {
						fmt.Printf("Starting MCP server on %s:%s for rafts: %v\n", cmdCfg.Host, cmdCfg.Port, cmdCfg.Names)
					}
					if err = cove.MCP(cmdCfg); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
						return err
					}
					return nil
				},
			},
		},
	}).Run()
}

func newCove(ctx context.Context, log *slog.Logger, cfg *domain.Config) (*r0mp.Cove, error) {
	regClient, err := image.NewDefaultCachedClient(log)
	if err != nil {
		return nil, err
	}
	return r0mp.NewCove(
		ctx,
		log,
		cfg,
		regClient,
		secrets.NewSecretStore(cfg.SecretStorePassword()),
		newPolicyBuilder(cfg),
	), nil
}

func resetIfDefault[V comparable](value *V, def V) {
	var nilValue V
	if *value == def {
		*value = nilValue
	}
}

func newPolicyBuilder(cfg *domain.Config) *policy.PolicyBuilder {
	storePath := filepath.Join(cfg.ConfigDir, "policies")
	return policy.NewPolicyBuilder(storePath, secrets.NewSecretStore(cfg.SecretStorePassword()))
}
