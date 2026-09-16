-- migrations/003_allowed_rooms.sql
-- Adds per-rule source-room allow lists for port access control (§8.2).
-- The column stores a JSON array of RoomIDs, empty string means
-- "same room only" (the rule's default semantics).

ALTER TABLE port_rules ADD COLUMN allowed_rooms TEXT NOT NULL DEFAULT '';