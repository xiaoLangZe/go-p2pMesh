-- migrations/002_ipv4.sql
-- Adds IPv4 address support for room-based virtual networking.

-- Add IPv4 address column to nodes table.
-- This stores the node's virtual IPv4 address within its room's /24 subnet.
ALTER TABLE nodes ADD COLUMN ipv4_addr VARCHAR(15);

-- Create index for IPv4 address lookups.
CREATE INDEX IF NOT EXISTS idx_nodes_ipv4 ON nodes(ipv4_addr);

-- Add room subnet info to rooms table (for caching/verification).
ALTER TABLE rooms ADD COLUMN ipv4_subnet VARCHAR(18);
