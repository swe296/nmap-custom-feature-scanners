-- Custom Nmap script for scanning DNS port features.
-- This script scans the target DNS service to identify supported query features.

local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Run on UDP/TCP port 53 (DNS)
portrule = shortport.portnumber(53, {"udp", "tcp"})

action = function(host, port)
  local out = {}
  
  table.insert(out, "DNS Port Feature Scan for: " .. host.ip)
  table.insert(out, "---------------------------------------------")

  -- 1. Scan for Recursion Feature
  -- Send a query for a domain to check if the server supports recursive lookups
  local status, resp = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol })
  if status and resp and #resp > 0 then
    table.insert(out, "Recursion Feature: Enabled (Server resolves external domains)")
  else
    table.insert(out, "Recursion Feature: Disabled (Server restricts external queries)")
  end

  -- 2. Scan for Supported Query Types
  -- Test if the DNS port responds to common query types
  table.insert(out, "Supported Query Type Scans:")
  
  -- Test A Record query
  local a_status = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "A" })
  table.insert(out, string.format("  - IPv4 Lookups (A Records):    %s", a_status and "Supported" or "Unsupported/Refused"))

  -- Test AAAA Record query
  local aaaa_status = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "AAAA" })
  table.insert(out, string.format("  - IPv6 Lookups (AAAA Records):  %s", aaaa_status and "Supported" or "Unsupported/Refused"))

  -- Test MX Record query
  local mx_status = dns.query("google.com", { host = host.ip, port = port.number, proto = port.protocol, dtype = "MX" })
  table.insert(out, string.format("  - Mail Exchange (MX Records):   %s", mx_status and "Supported" or "Unsupported/Refused"))

  return stdnse.format_output(true, out)
end
