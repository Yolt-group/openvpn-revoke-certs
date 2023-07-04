package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func tidy(c *cli.Context) error {

	vaultPath := c.String("path")

	vaultClient, err := getClient(c)
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"tidy_cert_store": true,
		"safety_buffer":   "1h",
	}

	tidy, err := vaultClient.Logical().Write(vaultPath+"/tidy", data)
	if err != nil {
		return errors.Wrapf(err, "failed to tidy for vault-path %q", vaultPath)
	}

	fmt.Println(tidy.Warnings[0])

	return nil
}
