package print

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
)

func Test_Print_Message(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Message("Hello World")

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	assert.Equal(t, "Hello World\n", buf.String())
}

func Test_Print_SuccessMessage(t *testing.T) {
	var buf bytes.Buffer
	color.Output = &buf

	SuccessMessage("Success")

	assert.True(t, strings.Contains(buf.String(), "Success"))
}

func Test_Print_ErrorMessage(t *testing.T) {
	var buf bytes.Buffer
	color.Output = &buf

	ErrorMessage("Error")

	assert.True(t, strings.Contains(buf.String(), "Error"))
}

func Test_Print_WarningMessage(t *testing.T) {
	var buf bytes.Buffer
	color.Output = &buf

	WarningMessage("Warning")

	assert.True(t, strings.Contains(buf.String(), "Warning"))
}
