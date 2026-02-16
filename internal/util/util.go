package util

import (
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/print"
)

func ExitOnError(msg string, err error) {
	if err != nil {
		print.ErrorMessage(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}
