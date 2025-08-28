# Identity Lifecycle Automation

Automate **onboarding, role change, and offboarding** flows from a CSV/HRIS source into Okta (and AD/Azure AD if desired).

## Features
- DRY-RUN first (safe by default)
- Idempotent create/update (avoid duplicates)
- Simple mapping for roles → groups
- Logging to `logs/`

## Setup
1. Copy `.env.example` → `.env` and set values.
2. Create a `data/new_hires.csv` file or use the sample.
3. Run `python src/okta_onboard_from_csv.py` (DRY-RUN true by default).

## Sample Data
`data/new_hires.csv`:
```
firstName,lastName,email,department,role
Ada,Lovelace,ada.lovelace@example.com,Engineering,Dev
Grace,Hopper,grace.hopper@example.com,Security,Analyst
```

## Commands
- Dry-run onboarding:
```
DRY_RUN=true python src/okta_onboard_from_csv.py --csv data/new_hires.csv
```
- Real onboarding (DEV tenant only):
```
DRY_RUN=false python src/okta_onboard_from_csv.py --csv data/new_hires.csv
```

## Role → Group Mapping
Edit `config/role_map.json` to map roles to Okta groups.

## Hiring Signals
- Shows you can **turn HR data into accounts** automatically.
- Demonstrates **API use, error handling, logging, idempotency**.
