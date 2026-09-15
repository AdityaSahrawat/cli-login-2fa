package cli

import (
	"fmt"
	"io"
)

// PrintSuccess prints a success message to the writer.
func PrintSuccess(w io.Writer, msg string) {
	fmt.Fprintln(w, msg)
}

// PrintError prints a formatted user-facing error message to the writer.
func PrintError(w io.Writer, err error) {
	fmt.Fprintf(w, "Error: %s\n", err.Error())
}

// PrintInfo prints informational text.
func PrintInfo(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, format, a...)
}
