# BEC Incident Timeline Generator

A PowerShell-driven HTML timeline visualizer for Business Email Compromise (BEC) investigations and incident response reporting. Takes structured CSV data and produces a self-contained, interactive HTML timeline with alternating left/right branching layout, entity colour-coding, spoofed email detection, and tag-based categorization.

---

## What It Looks Like

The output is a single HTML file — no server required, no dependencies to install. Open it in any modern browser. Events are grouped by day and hour along a central trunk line, with each event card showing:

- Timestamp
- Event header
- Full structured description (supports email formatting with From / To / Subject / Message / Attachments)
- Colour-coded entity references with **SPOOFED** or **THREAT ACTOR** badges where applicable
- Tag pills with unique colours per tag across the entire timeline

---

## Files

| File | Description |
|------|-------------|
| `Generate-Timeline.ps1` | Main PowerShell script |
| `timeline_template.html` | HTML/CSS template — edit this to change styling |
| `timeline_sample.csv` | Sample BEC investigation timeline data |
| `entities_sample.csv` | Sample entity / email mapping data |

---

## Requirements

- PowerShell 5.1 or later (Windows built-in) or PowerShell 7+
- Any modern browser to view the output (Chrome, Edge, Firefox)
- No external modules or dependencies

---

## Quick Start

```powershell
.\Generate-Timeline.ps1 `
    -CsvPath       ".\timeline_sample.csv" `
    -TemplatePath  ".\timeline_template.html" `
    -EntityCsvPath ".\entities_sample.csv" `
    -OutputPath    ".\output.html"
```

Then open `output.html` in your browser.

The `-EntityCsvPath` parameter is optional. Omit it and the script runs without entity colour-coding.

---

## Timeline CSV Format

**Required columns:** `DateTime`, `EventHeader`, `EventDescription`  
**Optional column:** `Tags`

```
DateTime,EventHeader,EventDescription,Tags
2024-01-08 09:34:00,INITIAL ACCOUNT ACCESS,"Description: ...",Initial Access;Suspicious Login
```

### DateTime
Standard format: `yyyy-MM-dd HH:mm:ss`  
The script also attempts automatic parsing if the format differs.

### EventDescription
Plain text is fine. For richer output, use the structured email format:

```
Description: Narrative context explaining what happened.

From: sender@domain.com
To: recipient@domain.com
CC: other@domain.com
Subject: Email subject line here
Message: Body of the email as you want it displayed.
Attachments:
1. Filename_One.pdf
2. Filename_Two.pdf  [notes about the file]
```

For non-email events (logins, rule creation, fund transfers, etc.) use labelled fields that fit the event:

```
Description: Threat actor initiates ACH transfer.

Source IP: 185.220.101.47 (Tor exit node - Netherlands)
Session Duration: 31 minutes
Actions Taken:
- Exported contact list
- Staged malicious SVG payload
```

Line breaks in descriptions are preserved in the output. Long URLs and strings wrap automatically within the event card.

### Tags
Semicolon-separated. Up to 5 tags are displayed per event. Each unique tag gets a consistent colour across the entire timeline.

```
Initial Access;Credential Theft;Phishing
```

---

## Entity CSV Format

**Required columns:** `Entity`, `RealEmail`, `SpoofedEmails`

```
Entity,RealEmail,SpoofedEmails
Robert Chen - Harborview Title,robert.chen@harborviewtitle.com,r.chen@harborview-title-co.com
David Park - Attorney,davidpark@dparklegallaw.com,d.park@dparklegallaw-legal.com
Carol Nguyen - CPA,c.nguyen@nguyencpagroup.com,c.nguyen@nguyen-cpa-advisors.com
```

Multiple addresses in either column are separated by semicolons:

```
John Smith,jsmith@acme.com,john.smith@acme-corp.net;jsmith@acme-secure.com
```

### How Entity Matching Works

When the script processes event descriptions it scans for known email addresses and replaces them with a colour-coded `Entity <email>` span. Each entity row in the CSV is assigned a unique colour from a 15-colour palette in order of appearance.

- **Real email found in text** → rendered in entity colour, no badge
- **Spoofed email found in text** → rendered in entity colour + red **SPOOFED** badge
- **THREAT_ACTOR token found in text** → rendered as entity name and real email + purple **THREAT ACTOR** badge

### THREAT_ACTOR Special Value

If `SpoofedEmails` is set to `THREAT_ACTOR` for an entity, it means the threat actor is sending as that person using their real email address. In your timeline CSV use the literal token `THREAT_ACTOR` anywhere the threat actor is acting as that entity:

**Entity CSV:**
```
Sarah Mitchell,smitchell@pinnaclerealty.com,THREAT_ACTOR
```

**Timeline CSV description:**
```
THREAT_ACTOR sends email to buyer confirming fraudulent ACH instructions.
```

**Rendered output:**  
`Sarah Mitchell <smitchell@pinnaclerealty.com>` ◼ **THREAT ACTOR**

When `smitchell@pinnaclerealty.com` appears in text from a legitimate context (Sarah actually sent it) it renders in her colour with no badge.

---

## Customising the Output

All visual styling lives in `timeline_template.html`. The key values to tweak:

| What | Where in template | Default |
|------|-------------------|---------|
| Event card width | `.event-card` → `max-width` | `clamp(200px, 28vw, 600px)` |
| Trunk line colour | `:root` → `--lc` | `#1a1a2e` |
| Day badge colour | `:root` → `--day-bg` / `--day-border` | Indigo palette |
| Hour badge colour | `:root` → `--hour-bg` / `--hour-border` | Indigo palette |
| Body background | `body` → `background` | `#f0f2f8` |
| SPOOFED badge colour | `.spoof-badge` → `background` | `#c62828` (red) |
| THREAT ACTOR badge colour | `.threat-actor-badge` → `background` | `#6a1b9a` (purple) |

The entity colour palette is defined in `Generate-Timeline.ps1` in the `$PALETTE` array (15 colours). Tag colours use a separate `$TAG_PALETTE` array. Both can be extended or replaced.

---

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | Yes | — | Path to the timeline CSV file |
| `-TemplatePath` | Yes | — | Path to the HTML template file |
| `-OutputPath` | No | `timeline_output.html` | Path for the generated HTML output |
| `-EntityCsvPath` | No | — | Path to the entity/email mapping CSV |
| `-DateTimeFormat` | No | `yyyy-MM-dd HH:mm:ss` | DateTime parse format for the timeline CSV |

---

## Use Cases

- **BEC / Email Fraud Investigations** — map the full kill chain from phishing through ACH fraud with real and spoofed actor communications clearly differentiated
- **Incident Response Reporting** — produce client-ready timeline deliverables from investigation notes
- **Tabletop Exercises** — build scenario timelines for BEC or phishing simulation exercises
- **Legal and Insurance Documentation** — structured, readable timeline output suitable for counsel and claims
- **Threat Intelligence** — document actor TTPs with attribution colour-coding across a campaign

---

## Tips

- **Excel users:** Save your CSV as *CSV UTF-8 (Comma delimited)* from the Save As dialog to avoid encoding issues with special characters. If that option is not available use *CSV (Comma delimited)* — the script handles both.
- **Long descriptions:** The script preserves line breaks. Use blank lines between sections (Description, From, To, etc.) for clean card rendering.
- **Commas in descriptions:** Excel will automatically quote cells containing commas when saving as CSV. If editing in a text editor wrap any description containing commas in double quotes.
- **Tag consistency:** Tags are matched case-insensitively for colour assignment. `Initial Access` and `initial access` will receive the same colour.
- **Many entities:** The palette cycles after 15 entities. For investigations with more than 15 distinct entities add additional colours to `$PALETTE` in the script.

---

## License

MIT — use freely, attribution appreciated but not required.
