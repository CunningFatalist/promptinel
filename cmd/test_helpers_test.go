package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func captureStdout(t *testing.T, run func()) string {
	t.Helper()

	previous := os.Stdout
	reader, writer, err := os.Pipe()

	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}

	os.Stdout = writer

	run()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	os.Stdout = previous

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	return buf.String()
}
