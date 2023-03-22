# A PowerShell script that looks up SPF, DKIM, and DMARC records for Google Workspace and Microsoft 365 domains.
# Author: Nick Marsh

# Run as an interactive script or accept the first argument as a domain.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName
)

Clear-Host

# Prompt for domain if not specified as an argument
if (-not $DomainName) {
    $DomainName = Read-Host "Enter the domain name to check (e.g. example.com)"
} else {
    Write-Host "Domain: $DomainName"
}

# Find the MX
$mxRecords = (Resolve-DnsName -Type MX -Name $DomainName | Sort-Object Priority).NameExchange
$mxGoogle = $mxRecords | Where-Object {$_ -like "*google*"}
$mxMicrosoft = $mxRecords | Where-Object {$_ -like "*outlook*"}

# Lookup DMARC
if ($mxGoogle) {
        $dkimSelector = "google"
    Write-Host "`nGoogle Workspace MX detected:"
    Write-Host -ForegroundColor Green "$mxGoogle"
} elseif ($mxMicrosoft) {
        $dkimSelector = "selector1","selector2"
    Write-Host "`nMicrosoft 365 MX detected:"
    Write-Host  -ForegroundColor Green "$mxMicrosoft"
} else {
    Write-Host -ForegroundColor Red "No valid Google Workspace or Microsoft 365 MX records were found for the domain $DomainName."
    exit
}

# Lookup SPF and print results
$sfpRecord = (Resolve-DnsName -Type TXT -ErrorAction SilentlyContinue -Name $DomainName).Strings | Where-Object {$_ -like "*v=spf1*" }

if ($sfpRecord) {
    # Check for duplicate TXT records
    $sfpRecordCount = $sfpRecord.Count
    if ($sfpRecordCount -gt 1) {
        Write-Host -ForegroundColor Red "`nWARNING: Multiple SPF TXT records found for ${DomainName}:"
        foreach ($record in $sfpRecord) {
            Write-Host $record
        }
    } else {
        Write-Host "`nSPF record detected:"
        # Check syntax of SPF record
        if ($sfpRecord -clike "v=spf1*") {
            Write-Host -ForegroundColor Green "$sfpRecord"
        } else {
            Write-Host -ForegroundColor Red "ERROR: Invalid SPF record found for ${DomainName}:"
            Write-Host $sfpRecord
        }
    }
} elseif (!$sfpRecord) {
    Write-Host -ForegroundColor Red "No SPF record was found for the domain $DomainName."
}

#Lookup DMARC and print results
$dmarcRecord = (Resolve-DnsName -Type TXT -ErrorAction SilentlyContinue -Name "_dmarc.$DomainName").Strings | Where-Object {$_ -like "v=DMARC1*"}

if ($dmarcRecord) {
    # Check for duplicate TXT records
    # NICE!
    $dmarcRecordCount = $dmarcRecord.Count
    if ($dmarcRecordCount -gt 1) {
        Write-Host -ForegroundColor Red "WARNING: Multiple DMARC TXT records found for ${DomainName}:"
        foreach ($record in $dmarcRecord) {
            Write-Host $record
        }
    } else {
        Write-Host "`nDMARC record detected:"
        # Check syntax of DMARC record
        if ($dmarcRecord -clike "v=DMARC1*") {
        Write-Host -ForegroundColor Green "$dmarcRecord"
        } else {
            Write-Host -ForegroundColor Red "ERROR: Invalid DMARC record found for ${DomainName}:"
            Write-Host $dmarcRecord
        }
    }
} elseif (!$dmarcRecord) {
    Write-Host -ForegroundColor Red "`nNo DMARC record was found for the domain ${DomainName}."
}

# Lookup DKIM and print results
foreach ($selector in $dkimSelector) {
    $dkimRecord = (Resolve-DnsName -Type TXT -ErrorAction SilentlyContinue -Name "$selector._domainkey.$DomainName").Strings | Where-Object {$_ -like "*=DKIM1*"}
    if ($dkimRecord) {
        # Check for duplicate TXT records
        $dkimRecordCount = $dkimRecord.Count
        if ($dkimRecordCount -gt 1) {
            Write-Host -ForegroundColor Red "WARNING: Multiple DKIM TXT records found for $selector._domainkey.${DomainName}:"
            foreach ($record in $dkimRecord) {
                Write-Host $record
            }
        } else {
            Write-Host "`nDKIM record detected for $selector._domainkey.${DomainName}:"
            # Check syntax of DKIM record
            if ($dkimRecord -like "*=DKIM1*") {
                Write-Host  -ForegroundColor Green "$dkimRecord"
            } else {
                Write-Host -ForegroundColor Red "ERROR: Invalid DKIM record found for $selector._domainkey.${DomainName}:"
                Write-Host $dkimRecord
            }
        }
    } else {
        Write-Host  -ForegroundColor Red "`nNo DKIM record was found for selector $selector._domainkey.$DomainName."
    }
}
