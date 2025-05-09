# FireMon NSG Tag Mapper

A Python utility script for mapping Azure Network Security Group (NSG) tags to FireMon rule documentation fields.

## Overview

This script automates the process of transferring Azure NSG tags to corresponding FireMon rule documentation fields. The script maps each NSG tag to its corresponding FireMon documentation field by name, maintaining the direct relationship between tag names and field names.

For example, if an Azure NSG has a tag "Owner: Networking", the script will find the FireMon "Owner" documentation field and set its value to "Networking".

## Prerequisites

- Python 3.6 or higher
- Access to a FireMon Security Manager instance
- Valid FireMon credentials with API access
- Azure NSGs with tags configured in FireMon

## Installation

Download the script to your FireMon server or a machine with access to your FireMon server:

```bash
curl -o firemon_nsg_documentation.py https://raw.githubusercontent.com/adamgunderson/FireMon-NSG-Tag-Mapper/refs/heads/main/firemon_nsg_documentation.py
# OR
wget https://raw.githubusercontent.com/adamgunderson/FireMon-NSG-Tag-Mapper/refs/heads/main/firemon_nsg_documentation.py
```

## Usage

### Basic Usage

Run the script in interactive mode:

```bash
python3 firemon_nsg_documentation.py
```

The script will prompt you for:
- FireMon server IP or FQDN
- Username and password
- Device selection
- Confirmation before updating fields

### Command Line Arguments

For automation or scheduled tasks, you can provide all parameters via command line:

```bash
./firemon_nsg_documentation.py --ip firemon.example.com --username admin --password mypassword --device 1372
```

### Available Options

| Option | Description |
|--------|-------------|
| `--ip` | FireMon app server IP or FQDN |
| `--domain` | Domain ID (default: 1) |
| `--device` | Device ID |
| `--username` | FireMon username |
| `--password` | FireMon password |
| `--batch-size` | Number of policies to update in a single batch (default: 10) |
| `--dry-run` | Show what would be updated without making changes |
| `--verbose` | Enable detailed logging |
| `--show-all-devices` | Show all devices including ones with 0 policies |
| `--tag-map` | Path to custom mapping JSON file |
| `--ignore-case` | Ignore case when matching tag names to documentation fields |

## Tag Matching Logic

The script matches NSG tags to FireMon documentation fields using the following process:

1. First, it looks for an exact match between the tag name and field name
2. If `--ignore-case` is enabled, it performs case-insensitive matching
3. If a custom mapping file is provided, it uses those mappings instead
4. When a match is found, the NSG tag value is assigned to the corresponding field

### Custom Tag Mapping

If your NSG tag names don't match FireMon field names exactly, you can create a custom mapping file:

```json
{
  "Tech-Owner": "Owner",
  "Cost-Center": "Cost Center",
  "Applications-Dept": "Business Unit",
  "Line-Of-Business": "Business Justification",
  "Environment": "Disaster Recovery"
}
```

Save this as a JSON file and provide the path with the `--tag-map` option:

```bash
python3 firemon_nsg_documentation.py --ip firemon.example.com --username admin --password mypassword --device 1372 --tag-map my_mapping.json
```

## Examples

### Basic Tag Mapping

```bash
python3 firemon_nsg_documentation.py --ip firemon.example.com --username admin --password mypassword
```

### Dry Run to Test Mapping

```bash
./firemon_nsg_documentation.py --ip firemon.example.com --username admin --password mypassword --dry-run --verbose
```

### Using Custom Mapping with Case Insensitivity

```bash
./firemon_nsg_documentation.py --ip firemon.example.com --username admin --password mypassword --tag-map mapping.json --ignore-case
```

## Troubleshooting

### Common Issues

1. **Authentication Failure**
   - Verify your username and password
   - Ensure your account has API access rights

2. **No Devices Found**
   - Check your domain ID (default is 1)
   - Ensure you have access to view devices

3. **No Policies Found**
   - Use `--show-all-devices` to view all devices regardless of policy count
   - Ensure Azure NSGs are properly imported into FireMon

4. **No Fields Mapped**
   - Use `--verbose` to see detailed matching attempts
   - Check if field names match tag names or create a custom mapping
   - Ensure NSGs have tags in Azure and they're visible in FireMon

### Running Directly on FireMon Server

If running directly on a FireMon server, the script includes a module import mechanism that searches for required libraries in standard FMOS paths.

## License

This script is provided "as is" without warranty of any kind, express or implied.
