package domain

type CommandRun struct {
	Name              string
	Image             string
	Memory            string
	Policy            string
	CPU               uint
	VolumeSizeBytes   int64
	Volumes           []string
	Environment       map[string]string
	Ports             []Ports
	IngressProxyPorts []IngressProxyPort
}

type CommandStart struct {
	Name string
}

type CommandSetupSecrets struct{}

type CommandPolicy struct {
	PolicyName string
	RuleName   string
	RaftName   string
	Source     string
	Target     string
	Domain     []string
	Path       []string
	Method     []string
	Schemes    []string
	Type       string
	Position   int
}

type CommandExec struct {
	Name        string
	Command     string
	EnableTTY   bool
	Interactive bool
	NoChroot    bool
	Detach      bool
	Environment map[string]string
	Args        []string
}

type CommandList struct{}

type CommandGet struct {
	Names []string
}

type CommandRemove struct {
	Names []string
}

type CommandImagesList struct{}

type CommandImagesRemove struct {
	References []string
}

type CommandImagesImport struct {
	TarPath   string
	Reference string
	All       bool
}

type CommandStop struct {
	Names []string
}

type CommandKill struct {
	Names []string
}

type CommandCopy struct {
	Source      string
	Destination string
	NoChroot    bool
}

type CommandMCP struct {
	Names []string
	Host  string
	Port  string
	StdIO bool
}
