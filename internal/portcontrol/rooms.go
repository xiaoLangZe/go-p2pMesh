package portcontrol

import (
	"encoding/json"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// encodeAllowedRooms serialises a room list to the JSON text form the
// storage column expects. Empty or nil lists encode as "" (the storage
// default), which the rule semantics read as "same room only".
func encodeAllowedRooms(rooms []types.RoomID) string {
	if len(rooms) == 0 {
		return ""
	}
	names := make([]string, len(rooms))
	for i, r := range rooms {
		names[i] = string(r)
	}
	b, err := json.Marshal(names)
	if err != nil {
		return ""
	}
	return string(b)
}

// decodeAllowedRooms parses the storage JSON form back into a room list.
// Malformed input yields an empty list — never a parse error — because a
// corrupt column should fall back to the stricter default (same room),
// not disable the rule or crash the client.
func decodeAllowedRooms(raw string) []types.RoomID {
	if raw == "" {
		return nil
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil {
		return nil
	}
	rooms := make([]types.RoomID, 0, len(names))
	for _, n := range names {
		rooms = append(rooms, types.RoomID(n))
	}
	return rooms
}
