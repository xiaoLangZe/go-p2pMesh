package dht

import "errors"

var (
	errNilNode  = errors.New("dht: nil node")
	errSelfNode = errors.New("dht: cannot store the local node in its own table")
)