package main

import (
	"os"

	"github.com/urfave/cli/v2"
)

var (
	version = "20.0.0"
)

func main() {

	app := cli.NewApp()
	app.Version = version
	app.Usage = "CLI for create CRL for openvpn"
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "address",
			Aliases: []string{"a"},
			Usage:   "The Vault address",
			EnvVars: []string{"VAULT_ADDR"},
		},
		&cli.StringFlag{
			Name:    "token",
			Aliases: []string{"t"},
			Usage:   "The Vault token ( you should always export token as variable )",
			EnvVars: []string{"VAULT_TOKEN"},
		},
		&cli.StringFlag{
			Name:    "context",
			Aliases: []string{"c"},
			Value:   "dta",
			Usage:   "Configuration context (dev, dta or prd)",
		},
		&cli.StringFlag{
			Name:    "path",
			Aliases: []string{"p"},
			Value:   "management-prd/newvpn",
			Usage:   "Specify pki vault path",
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List high-privileged secret roles",
			Action:  checkError(list),
		},
		{
			Name:    "tidy",
			Aliases: []string{"t"},
			Usage:   "Clear all expired certs from vault",
			Action:  checkError(tidy),
		},
		{
			Name:    "getcrl",
			Aliases: []string{"g"},
			Usage:   "Get CRL certificate from vault",
			Action:  checkError(getcrl),
		},
		{
			Name:    "revoke",
			Aliases: []string{"r"},
			Usage:   "revoke",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "file, f",
					Usage: "Specify file with list of certificates to revoke in format: certificateSerial;CommonName",
					Value: "revoke-prd.list",
				},
				&cli.StringFlag{
					Name:  "save, s",
					Usage: "save crl certificate to file",
				},
			},
			Action: checkError(revoke),
		},
	}

	app.Run(os.Args)
}
