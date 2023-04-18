package scan

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func ExportFile(filename string) (*os.File, error) {
	name := filename
	if filename == "" {
		name = fmt.Sprintf("code-security-report-%d.html", time.Now().Unix())
		name = strings.ReplaceAll(name, "/", "-")
	} else {
		if !strings.HasSuffix(name, ".html") {
			name = fmt.Sprintf("%s.html", name)
		}
	}

	return os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0644)
}
