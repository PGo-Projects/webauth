package response

import (
	"fmt"
	"strings"
)

const (
	StatusSuccess string = "success"
	StatusInfo    string = "info"
	StatusError   string = "error"
	StatusWarning string = "warning"
)

func Status(status string, statusType string) string {
	responseTemplate := `{"status": "%s", "statusType": "%s"}`
	return fmt.Sprintf(responseTemplate, status, statusType)
}

func General(payload map[string]string) string {
	var response strings.Builder
	response.WriteByte('{')

	i := 1
	keyValueTemplate := `"%s": "%s"`
	for key, val := range payload {
		response.WriteString(fmt.Sprintf(keyValueTemplate, key, val))
		if i < len(payload) {
			response.WriteByte(',')
		}
		i += 1
	}

	response.WriteByte('}')
	return response.String()
}
