package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

type revokeData struct {
	serial     string
	commonName string
}

func revoke(c *cli.Context) error {

	vaultPath := c.String("path")

	vaultClient, err := getClient(c)
	if err != nil {
		return err
	}

	revokeListFile := c.String("file")
	revokeListRaw, err := readFile(revokeListFile)
	if err != nil {
		return errors.Wrapf(err, "Cant't get  %q", vaultPath)
	}

	revokeList, err := convertList(revokeListRaw)
	if err != nil {
		return errors.Wrapf(err, "something is wrong with revoke list in file  %s", revokeListFile)
	}

	certsList, err := getCertsList(vaultClient, vaultPath)
	if err != nil {
		return err
	}

	for _, rl := range revokeList {
		if contains(certsList, rl.serial) {
			certificate, err := getCertificate(vaultClient, vaultPath, rl.serial)
			if err != nil {
				return err
			}

			if certificate.Subject.CommonName != rl.commonName {
				return fmt.Errorf("certificate with serial: %s, has different common name value", rl.serial)
			}
		}

		data := map[string]interface{}{
			"serial_number": rl.serial,
		}

		revokeCert, err := vaultClient.Logical().Write(vaultPath+"/revoke", data)
		if err != nil {
			return errors.Wrapf(err, "failed to revoke certificate: %s", rl.serial)
		}

		log.Printf("Certificate: %s, revoked. Time: %v", rl.serial, revokeCert.Data["revocation_time_rfc3339"])
	}

	crl, err := getCRLCertificate(c)
	if err != nil {
		return err
	}

	fmt.Println(string(crl))

	if c.String("save") != "" {
		err := writeFile(c.String("save"), crl)
		if err != nil {
			return err
		}
	}

	return nil
}

func convertList(list []string) ([]revokeData, error) {

	var revoke []revokeData

	isSerial := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`).MatchString
	isCommonName := regexp.MustCompile(`^[a-zA-Z0-9\.\@\-]+$`).MatchString

	for nr, line := range list {
		l := strings.Split(line, ";")

		serial := l[0]
		commonName := l[1]

		if !isSerial(serial) {
			return nil, fmt.Errorf("line: %d, serial: %s has incorrect value", nr, serial)
		}

		if !isCommonName(commonName) {
			return nil, fmt.Errorf("line: %d, commonName: %s has incorrect value", nr, commonName)
		}

		var rl revokeData
		rl.serial = serial
		rl.commonName = commonName

		revoke = append(revoke, rl)

	}
	return revoke, nil
}
