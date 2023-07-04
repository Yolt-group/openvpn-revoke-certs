package main

import (
	"bufio"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func checkError(a cli.ActionFunc) cli.ActionFunc {
	return func(c *cli.Context) error {
		err := a(c)
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		return nil
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func readFile(path string) ([]string, error) {
	var l []string

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		l = append(l, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return l, nil
}

func writeFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	defer f.Close()

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
