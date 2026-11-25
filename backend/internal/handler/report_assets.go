package handler

import (
	_ "embed"
	"encoding/base64"
)

//go:embed report_sophon_logo.png
var reportSophonLogo []byte

func reportSophonLogoDataURL() string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(reportSophonLogo)
}
