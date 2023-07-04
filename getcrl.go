package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/urfave/cli/v2"
)

func getcrl(c *cli.Context) error {

	body, err := getCRLCertificate(c)
	if err != nil {
		return err
	}

	fmt.Println(string(body))

	return nil
}

func getCRLCertificate(c *cli.Context) ([]byte, error) {
	vaultPath := c.String("path")
	vaultAddr := ""

	if c.String("address") != "" {
		vaultAddr = c.String("address")
	} else {
		vaultAddr = "https://vault.yolt.io"
	}

	resp, err := http.Get(fmt.Sprintf("%s/v1/%s/crl/pem", vaultAddr, vaultPath))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
