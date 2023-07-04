package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func list(c *cli.Context) error {

	vaultPath := c.String("path")

	vaultClient, err := getClient(c)
	if err != nil {
		return err
	}

	list, err := getCertsList(vaultClient, vaultPath)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Nr", "Serial", "CN", "notAfter"})

	for nr, serial := range list {
		certificate, err := getCertificate(vaultClient, vaultPath, serial)
		if err != nil {
			return err
		}

		subjectCN := certificate.Subject.CommonName
		notAfter := certificate.NotAfter.UTC().String()

		table.Append([]string{strconv.Itoa(nr + 1), serial, subjectCN, notAfter})
		time.Sleep(100 * time.Millisecond)
	}

	table.Render()
	return nil
}

func getCertsList(vaultClient *api.Client, vaultPath string) ([]string, error) {
	certsList, err := vaultClient.Logical().List(vaultPath + "/certs")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list to vault-path %q", vaultPath)
	}

	tmpList := fmt.Sprintf("%v", certsList.Data["keys"])
	tmpList = strings.Replace(tmpList, "[", "", -1)
	tmpList = strings.Replace(tmpList, "]", "", -1)

	list := strings.Split(tmpList, " ")

	return list, err
}

func getCertificate(vaultClient *api.Client, vaultPath string, serial string) (*x509.Certificate, error) {
	cert, err := vaultClient.Logical().Read(vaultPath + "/cert/" + serial)
	if err != nil {
		return &x509.Certificate{}, errors.Wrapf(err, "failed to read cert for:  %q", serial)
	}

	userCert := cert.Data["certificate"].(string)

	certPem, _ := pem.Decode([]byte(userCert))
	certificate, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return &x509.Certificate{}, errors.Wrapf(err, "failed to read cert for:  %q", serial)
	}

	return certificate, nil
}
