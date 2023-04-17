package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/oscarzhou/code-security-report/cmd"
	"github.com/oscarzhou/code-security-report/logutil"
)

func main() {

	cli := cmd.CLI{}
	cliCtx := kong.Parse(&cli,
		kong.Name("code-security-report"),
		kong.Description("A tool to compare security report from different tools"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
		kong.Vars{
			"version": cmd.TOOL_VERSION,
		})

	logutil.ConfigureLogger(cli.PrettyLog)
	logutil.SetLoggingLevel(logutil.Level(cli.LogLevel))

	err := cliCtx.Run()
	if err != nil {
		fmt.Println("err=", err)
		cliCtx.FatalIfErrorf(err)
	}
	os.Exit(0)
}
