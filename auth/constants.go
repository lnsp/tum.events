package auth

import "regexp"

var LoginKeyRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var LoginCodeRegex = regexp.MustCompile(`^[0-9]{6}$`)
