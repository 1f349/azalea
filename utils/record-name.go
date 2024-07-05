package utils

import "strings"

// ResolveRecordName expands shortened record names relative to the provided zone
//
// The name "" is equivalent to "@"
//
// - ("@", "example.com.") -> "example.com."
// - ("ns1", "example.com.") -> "ns1.example.com."
// - ("ns2.example.com.", "example.org.") -> "ns2.example.com."
// - ("ns3", "") -> "ns3."
func ResolveRecordName(name, zone string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	// resolve @ and relative names
	switch name {
	case "@", "":
		name = zone
	default:
		name = name + "." + zone
	}
	return name
}

// SimplifyRecordName shortens the record name relative to the provided zone
//
// - ("example.com.", "example.com.") -> "@"
// - ("ns1.example.com.", "example.com.") -> "ns1"
// - ("ns2.example.com.", "example.org.") -> "ns2.example.com."
func SimplifyRecordName(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}
