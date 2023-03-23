#!/bin/bash

# A Bash script that looks up SPF, DKIM, and DMARC records for Google Workspace and Microsoft 365 domains.
# Author: Nick Marsh
# Note: Tested on Linux and macOS

clear

# Accept the first argument as a domain.
DomainName=$1

# Prompt for domain if not specified as an argument
if [[ -z "$DomainName" ]]; then
  read -p "Enter the domain name to check (e.g. example.com): " DomainName
else
  echo "Domain: $DomainName"
fi

# Find the MX
mxRecords=$(dig +short MX $DomainName | sort -n -k 1 | awk '{print $2}')
mxGoogle=$(echo "$mxRecords" | grep -i "google")
mxMicrosoft=$(echo "$mxRecords" | grep -i "outlook")

# Lookup DMARC
if [[ -n "$mxGoogle" ]]; then
  dkimSelector="google"
  echo -e "\nGoogle Workspace MX detected:"
  echo -e "\033[32m$mxGoogle\033[0m\n"
elif [[ -n "$mxMicrosoft" ]]; then
  dkimSelector=("selector1" "selector2")
  echo -e "\nMicrosoft 365 MX detected:"
  echo -e "\033[32m$mxMicrosoft\033[0m\n"
else
  echo -e "\033[31mNo valid Google Workspace or Microsoft 365 MX records were found for the domain $DomainName.\033[0m"
  exit 1
fi

# Lookup SPF and print results
sfpRecord=$(dig +short TXT $DomainName | grep "v=spf1")

if [[ -n "$sfpRecord" ]]; then
  # Check for duplicate TXT records
  sfpRecordCount=$(echo "$sfpRecord" | wc -l)
  if [[ "$sfpRecordCount" -gt 1 ]]; then
    echo -e "\033[31m\nWARNING: Multiple SPF TXT records found for ${DomainName}:\033[0m"
    echo "$sfpRecord\n"
  else
    echo -e "\nSPF record detected:"
    # Check syntax of SPF record
    if [[ "$sfpRecord" =~ ^\"v=spf1 ]]; then
      echo -e "\033[32m$sfpRecord\033[0m\n"
    else
      echo -e "\033[31mERROR: Invalid SPF record found for ${DomainName}:\033[0m\n"
      echo "$sfpRecord\n"
    fi
  fi
else
  echo -e "\033[31mNo SPF record was found for the domain $DomainName.\033[0m\n"
fi

# Lookup DMARC and print results
dmarcRecord=$(dig +short TXT "_dmarc.$DomainName" | grep "v=DMARC1")

if [[ -n "$dmarcRecord" ]]; then
  # Check for duplicate TXT records
  dmarcRecordCount=$(echo "$dmarcRecord" | wc -l)
  if [[ "$dmarcRecordCount" -gt 1 ]]; then
    echo -e "\033[31mWARNING: Multiple DMARC TXT records found for ${DomainName}:\033[0m\n"
    echo "$dmarcRecord\n"
  else # NICE!
    echo -e "\nDMARC record detected:"
    # Check syntax of DMARC record
    if [[ "$dmarcRecord" =~ ^\"v=DMARC1 ]]; then
      echo -e "\033[32m$dmarcRecord\033[0m\n"
    else
      echo -e "\033[31mERROR: Invalid DMARC record found for ${DomainName}:\033[0m\n"
      echo "$dmarcRecord\n"
    fi
  fi
else
  echo -e "\033[31mNo DMARC record was found for the domain ${DomainName}.\033[0m\n"
fi

# Lookup DKIM and print results
for selector in "${dkimSelector[@]}"; do
  dkimRecord=$(dig +short TXT "$selector._domainkey.$DomainName" | grep "=DKIM1")
  if [[ -n "$dkimRecord" ]]; then
    # Check for duplicate TXT records
    dkimRecordCount=$(echo "$dkimRecord" | wc -l)
    if [[ "$dkimRecordCount" -gt 1 ]]; then
      echo -e "\033[31mWARNING: Multiple DKIM TXT records found for $selector._domainkey.${DomainName}:\033[0m\n"
      echo "$dkimRecord\n"
    else
      echo -e "\nDKIM record detected for $selector._domainkey.${DomainName}:"
      # Check syntax of DKIM record
      if [[ "$dkimRecord" =~ ^\"v=DKIM1 ]]; then
        echo -e "\033[32m$dkimRecord\033[0m\n"
      else
        echo -e "\033[31mERROR: Invalid DKIM record found for $selector._domainkey.${DomainName}:\033[0m\n"
        echo "$dkimRecord\n"
      fi
    fi
  else
    echo -e "\033[31mNo DKIM record was found for selector $selector._domainkey.$DomainName.\033[0m\n"
  fi
done
