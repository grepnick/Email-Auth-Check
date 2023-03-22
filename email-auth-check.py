#!/usr/bin/env python3

# A PowerShell script that looks up SPF, DKIM, and DMARC records for Google Workspace and Microsoft 365 domains.
# Credit: Nick Marsh

# Run as an interactive script or accept the first argument as a domain.

import dns.resolver
import os
import sys
import subprocess

# Clear the screen
os.system('cls' if os.name == 'nt' else 'clear')

# Prompt for domain if not specified as an argument
if len(sys.argv) > 1:
    domain_name = sys.argv[1]
else:
    domain_name = input("Enter the domain name to check (e.g. example.com): ")

print(f"\nDomain: {domain_name}")

# Find the MX
try:
     mx_records = sorted(dns.resolver.resolve(domain_name, 'MX'), key=lambda r: r.preference)
except dns.resolver.NXDOMAIN:
    print("\033[31m" + f"\nNo MX record was found for the domain {domain_name}."  + "\033[0m")
    mx_records = []
except dns.resolver.NoAnswer:
    mx_records = []
    pass


mx_google = [mx.exchange.to_text() for mx in mx_records if 'google' in mx.exchange.to_text().lower()]
mx_microsoft = [mx.exchange.to_text() for mx in mx_records if 'outlook' in mx.exchange.to_text().lower()]

# Lookup MX
if mx_google:
    dkim_selector = "google"
    print("\nGoogle Workspace MX detected:")
    print("\033[32m" + "\n".join(mx_google) + "\033[0m")
elif mx_microsoft:
    dkim_selector = ["selector1", "selector2"]
    print("\nMicrosoft 365 MX detected:")
    print("\033[32m" + "\n".join(mx_microsoft) + "\033[0m")
else:
    print("\033[31m" + f"\nNo valid Google Workspace or Microsoft 365 MX records were found for the domain {domain_name}." + "\033[0m")
    exit()

# Lookup SPF and print results
try:
    spf_records = [r.strings[0].decode() for r in dns.resolver.resolve(domain_name, 'TXT') if 'v=spf1' in r.strings[0].decode()]
except dns.resolver.NXDOMAIN:
    print("\033[31m" + f"\nNo SPF record was found for the domain {domain_name}."  + "\033[0m")
    spf_records = []
except dns.resolver.NoAnswer:
    spf_records = []
    pass

if spf_records:
    # Check for duplicate TXT records
    spf_record_count = len(spf_records)
    if spf_record_count > 1:
        print("\033[31m" + f"\nWARNING: Multiple SPF TXT records found for {domain_name}:" + "\033[0m")
        for record in spf_records:
            print(record)
    else:
        # NICE!
        print("\nSPF record detected:")
        # Check syntax of SPF record
        if spf_records[0].startswith("v=spf1"):
            print("\033[32m" + spf_records[0] + "\033[0m")
        else:
            print("\033[31m" + f"ERROR: Invalid SPF record found for {domain_name}:" + "\033[0m")
            print(spf_records[0])
elif not spf_records:
    print("\033[31m" + f"\nNo SPF record was found for the domain {domain_name}." + "\033[0m")

# Lookup DMARC and print results
try:
    dmarc_records = [r.strings[0].decode() for r in dns.resolver.resolve(f"_dmarc.{domain_name}", 'TXT') if 'v=DMARC1' in r.strings[0].decode()]
except dns.resolver.NXDOMAIN:
    print("\033[31m" + f"\nNo DMARC record was found for the domain {domain_name}." + "\033[0m")
    dmarc_records = []
    pass
except dns.resolver.NoAnswer:
    print("\033[31m" + f"\nNo DMARC record was found for the domain {domain_name}."  + "\033[0m")
    dmarc_records = []
    pass
if dmarc_records:
    # Check for duplicate TXT records
    dmarc_record_count = len(dmarc_records)
    if dmarc_record_count > 1:
        print("\033[31m" + f"WARNING: Multiple DMARC TXT records found for {domain_name}:" + "\033[0m")
        for record in dmarc_records:
            print(record)
    else:
        print("\nDMARC record detected:")
        # Check syntax of DMARC record
        if dmarc_records[0].startswith("v=DMARC1"):
            print("\033[32m" + dmarc_records[0] + "\033[0m")
        else:
            print("\033[31m" + f"ERROR: Invalid DMARC record found for {domain_name}:" + "\033[0m")
            print(dmarc_records[0])

# Lookup DKIM and print results
dkim_selector = ["google"] if mx_google else ["selector1", "selector2"]
for selector in dkim_selector:
    try:
        dkim_records = [r.strings[0].decode() for r in dns.resolver.resolve(f"{selector}._domainkey.{domain_name}", 'TXT') if 'v=DKIM1' in r.strings[0].decode()]
    except dns.resolver.NXDOMAIN:
        dkim_records = []
    except dns.resolver.NoAnswer:
        dkim_records = []
        pass
    if dkim_records:
        # Check for duplicate TXT records
        dkim_record_count = len(dkim_records)
        if dkim_record_count > 1:
            print("\033[31m" + f"WARNING: Multiple DKIM TXT records found for {selector}._domainkey.{domain_name}:" + "\033[0m")
            for record in dkim_records:
                print(record)
        else:
            print(f"\nDKIM record detected for {selector}._domainkey.{domain_name}:")
            # Check syntax of DKIM record
            if 'v=DKIM1' in dkim_records[0]:
                print("\033[32m" + dkim_records[0] + "\033[0m")
            else:
                print("\033[31m" + f"ERROR: Invalid DKIM record found for {selector}._domainkey.{domain_name}:" + "\033[0m")
                print(dkim_records[0])
    else:
        print("\033[31m" + f"\nNo DKIM record was found for selector {selector}._domainkey.{domain_name}.\n" + "\033[0m")
