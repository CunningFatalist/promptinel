package main

import (
	"os"
	"testing"
)

func Test_Main_InvokesCommandExecute(t *testing.T) {
	previousArgs := os.Args
	os.Args = []string{"promptinel", "--version"}
	t.Cleanup(func() {
		os.Args = previousArgs
	})

	main()
}
