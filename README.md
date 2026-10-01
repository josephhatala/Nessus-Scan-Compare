# Nessus-Scan-Compare
Compares the scans before patching and after patching and exports them to 3 .csv files to see how effective your patching was. 

The 3 files that are created are: 
  - Mitigated.csv
  - summary.csv
  - New.csv

To have these run, you need to export your Nessus report via csv  with the following fields:
  - Plugin ID
  - CVE
  - Risk
  - Host
  - Name

In the PowerShell script, you have to determine what path you'll be operating out of. Once the path is decided, you need to adjust these fields: 

$BeforeCsv = "Path where your pre patching scans were exported to\before.csv.csv"
$AfterCsv  = "Path where your post patching scans were exported to\after.csv.csv"

*** Note that if it is exported as a .csv, your Nessus file might have to have .csv.csv attached to it ***

$SummaryCsv   = "Where you want your summary csv placed\PatchSummary_$TimeStamp.csv"
$MitigatedCsv = "Where you want your mitigated cve file placed\MitigatedFindings_$TimeStamp.csv"
$NewCsv       = "Where you want your new cves that were discovered between scan dates placed\NewFindings_$TimeStamp.csv"

Script can take a few minutes to run, but it will also produce in Powershell a brief summary in the text box as well when completed. I hope this helps you analyze your patching analysis as it did for me!
