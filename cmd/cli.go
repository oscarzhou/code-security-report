package cmd

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/oscarzhou/code-security-report/logutil"
)

type Globals struct {
	LogLevel  logutil.Level `kong:"help='Set the logging level',default='INFO',enum='DEBUG,INFO,WARN,ERROR',env='LOG_LEVEL'"`
	PrettyLog bool          `kong:"help='Whether to enable or disable colored logs output',default='false',env='PRETTY_LOG'" optional:""`
	Version   VersionFlag   `name:"version" help:"Print the version"`
}

type VersionFlag string

func (v VersionFlag) Decode(ctx *kong.DecodeContext) error { return nil }
func (v VersionFlag) IsBool() bool                         { return true }
func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Println(vars["version"])
	app.Exit(0)
	return nil
}

type CLI struct {
	Globals
	Version VersionCommand `cmd:"" help:"Print the version"`
	Inspect InspectCommand `cmd:"" help:"Inspect the path"`
	Summary SummaryCommand `cmd:"" help:"Get a summary of the report"`
	Diff    DiffCommand    `cmd:"" help:"Get a diff of two reports"`
}
