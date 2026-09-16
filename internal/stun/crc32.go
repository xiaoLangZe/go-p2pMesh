package stun

import "hash/crc32"

// crc32Compute wraps the standard library's IEEE CRC-32.
// Kept in a separate file so client.go does not import hash/crc32 directly,
// which makes it easier to swap implementations if needed.
func crc32Compute(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
