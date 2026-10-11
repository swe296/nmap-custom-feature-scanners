-- Custom Nmap script for scanning TLS certificate features.
-- This script scans the target port to identify certificate metadata features.

local sslcert = require "sslcert"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Run on SSL/TLS enabled ports
portrule = shortport.ssl

action = function(host, port)
  local out = {}

  table.insert(out, "TLS Certificate Feature Scan for: " .. host.ip .. ":" .. port.number)
  table.insert(out, "---------------------------------------------")

  -- Scan and retrieve the remote SSL certificate features
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert then
    return "Error: Failed to retrieve certificate features from target."
  end

  -- Extract and list features
  table.insert(out, "Certificate Identity Features:")
  table.insert(out, "  - Subject (CN):       " .. (cert.subject.commonName or "Unknown"))
  table.insert(out, "  - Issuer (CN):        " .. (cert.issuer.commonName or "Unknown"))

  if cert.validity and cert.validity.notBefore and cert.validity.notAfter then
    local start = cert.validity.notBefore
    local expiry = cert.validity.notAfter
    table.insert(out, string.format("  - Validity Period:    %04d-%02d-%02d to %04d-%02d-%02d", 
      start.year, start.month, start.day, expiry.year, expiry.month, expiry.day))
  end

  table.insert(out, "Cryptographic Algorithm Features:")
  table.insert(out, "  - Signature Hash:     " .. (cert.sig_algorithm or "Unknown"))
  
  if cert.pubkey then
    local key_type = cert.pubkey.type or "Unknown"
    local key_bits = cert.pubkey.bits or 0
    table.insert(out, string.format("  - Public Key Cipher:  %s (%d bits)", key_type:upper(), key_bits))
  end

  return stdnse.format_output(true, out)
end
