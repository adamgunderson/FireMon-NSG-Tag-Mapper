#!/usr/bin/python
# firemon_nsg_documentation.py
import sys
import os
import importlib.util
import re

def ensure_module(module_name):
    """Dynamically import a module by searching for it in potential site-packages locations"""
    # First try the normal import in case it's already in the path
    try:
        return __import__(module_name)
    except ImportError:
        pass
    
    # Get the current Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    
    # Create a list of potential paths to check
    base_path = '/usr/lib/firemon/devpackfw/lib'
    potential_paths = [
        # Current Python version
        f"{base_path}/python{py_version}/site-packages",
        # Exact Python version with patch
        f"{base_path}/python{sys.version.split()[0]}/site-packages",
        # Try a range of nearby versions (for future-proofing)
        *[f"{base_path}/python3.{i}/site-packages" for i in range(8, 20)]
    ]
    
    # Try each path
    for path in potential_paths:
        if os.path.exists(path):
            if path not in sys.path:
                sys.path.append(path)
            try:
                return __import__(module_name)
            except ImportError:
                continue
    
    # If we get here, we couldn't find the module
    raise ImportError(f"Could not find module {module_name} in any potential site-packages location")

# Import required modules
requests = ensure_module("requests")
json = ensure_module("json")
urllib3 = ensure_module("urllib3")
getpass = ensure_module("getpass")
time = ensure_module("time")
argparse = ensure_module("argparse")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    """Parse command line arguments or prompt for inputs"""
    parser = argparse.ArgumentParser(description='Map NSG tags to FireMon rule documentation fields')
    parser.add_argument('--ip', help='FireMon app server IP or FQDN')
    parser.add_argument('--domain', type=int, default=1, help='Domain ID (default: 1)')
    parser.add_argument('--device', type=int, help='Device ID')
    parser.add_argument('--username', help='FireMon username')
    parser.add_argument('--password', help='FireMon password')
    parser.add_argument('--batch-size', type=int, default=10, help='Number of policies to update in a single batch')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--show-all-devices', action='store_true', help='Show all devices including ones with 0 policies')
    parser.add_argument('--tag-map', help='Custom mapping of NSG tags to rule documentation fields (JSON file)')
    parser.add_argument('--ignore-case', action='store_true', help='Ignore case when matching tag names to documentation fields')
    parser.add_argument('--non-interactive', action='store_true', help='Run without prompting for input (for cron jobs)')
    
    # Logging options
    parser.add_argument('--log-file', help='Path to log file (default: stdout only)')
    parser.add_argument('--log-max-size', type=int, default=10, help='Maximum log file size in MB (default: 10)')
    parser.add_argument('--log-backup-count', type=int, default=5, help='Number of log backup files to keep (default: 5)')

    args = parser.parse_args()

    # Check if we're in non-interactive mode and validate required parameters
    if args.non_interactive:
        missing_params = []
        if not args.ip:
            missing_params.append('--ip')
        if not args.username:
            missing_params.append('--username')
        if not args.password:
            missing_params.append('--password')
        if not args.device:
            missing_params.append('--device')
        
        if missing_params:
            print(f"Error: The following parameters are required in non-interactive mode: {', '.join(missing_params)}")
            sys.exit(1)
        return args

    # If not in non-interactive mode and args aren't provided, prompt for them
    if not args.ip:
        args.ip = input("FireMon app server IP or FQDN (default: localhost): >> ") or "localhost"
    
    if not args.username:
        args.username = input("Username for FireMon UI account: >> ")
    
    if not args.password:
        args.password = getpass.getpass('Password for FireMon UI account: >> ')
        
    return args

def setup_logging(verbose=False, log_file=None, log_max_size=10, log_backup_count=5):
    """Set up logging configuration with rotation support
    
    Args:
        verbose (bool): Whether to enable debug logging
        log_file (str): Path to log file (None for stdout only)
        log_max_size (int): Maximum log file size in MB
        log_backup_count (int): Number of backup files to keep
    """
    level = "DEBUG" if verbose else "INFO"
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    try:
        import logging
        from logging.handlers import RotatingFileHandler
        import os
        
        logger = logging.getLogger('firemon_nsg_documentation')
        logger.setLevel(getattr(logging, level))
        
        # Clear any existing handlers
        if logger.handlers:
            logger.handlers = []
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(console_handler)
        
        # Create file handler if log_file is specified
        if log_file:
            # Convert relative paths that start with ~/
            if log_file.startswith('~/'):
                log_file = os.path.expanduser(log_file)
                
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                except PermissionError:
                    logger.warning(f"Cannot create log directory {log_dir}. Check permissions.")
                except Exception as e:
                    logger.warning(f"Error creating log directory {log_dir}: {str(e)}")
            
            try:
                # Convert MB to bytes for maxBytes
                max_bytes = log_max_size * 1024 * 1024
                
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=max_bytes,
                    backupCount=log_backup_count
                )
                file_handler.setFormatter(logging.Formatter(log_format))
                logger.addHandler(file_handler)
                logger.info(f"Logging to file: {log_file} (max size: {log_max_size}MB, backups: {log_backup_count})")
            except PermissionError:
                logger.warning(f"Cannot write to log file {log_file}. Check permissions.")
            except Exception as e:
                logger.warning(f"Error setting up file logging: {str(e)}")
        
        return logger
    except ImportError:
        # Simple print-based logger if logging module is not available
        class SimpleLogger:
            def __init__(self, level):
                self.level = level
                self.levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
            
            def _log(self, level, msg):
                if self.levels.get(level, 0) >= self.levels.get(self.level, 0):
                    print(f"{level}: {msg}")
            
            def debug(self, msg): self._log("DEBUG", msg)
            def info(self, msg): self._log("INFO", msg)
            def warning(self, msg): self._log("WARNING", msg)
            def error(self, msg): self._log("ERROR", msg)
        
        return SimpleLogger(level)

def authenticate_session(ip, username, password, logger):
    """Authenticate with the FireMon API"""
    session = requests.Session()
    session.auth = (username, password)
    session.headers = {'Content-Type': 'application/json'}
    session.verify = False  # Disable SSL verification
    
    # Verify username/password and authenticate
    logon_data = {
        'username': username,
        'password': password
    }
    
    try:
        verify_auth = session.post(f'https://{ip}/securitymanager/api/authentication/validate', 
                                data=json.dumps(logon_data))
        
        if verify_auth.status_code != 200:
            logger.error("Authentication failed. Please check your username and/or password.")
            sys.exit(1)
        
        auth_status = verify_auth.json().get('authStatus', '')
        if auth_status == 'AUTHORIZED':
            logger.info("Authenticated successfully.")
            return session
        else:
            logger.error(f"Authorization failed with status: {auth_status}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        logger.error(f"Failed to connect to {ip}. Please check the server IP/FQDN and network connectivity.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        sys.exit(1)

def normalize_name(name):
    """Normalize field names for better matching"""
    # Convert to lowercase, remove special characters
    normalized = re.sub(r'[^\w\s]', '', name).lower()
    # Replace multiple whitespaces with single space
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized

def get_documentation_fields(ip, domain_id, session, logger):
    """Get available documentation fields"""
    url = f"https://{ip}/securitymanager/api/customproperty/domain/{domain_id}"
    
    try:
        response = session.get(url, params={"search": ""})
        if response.status_code != 200:
            logger.error(f"Failed to get documentation fields: {response.status_code} - {response.text}")
            return None
        
        fields = response.json()
        
        # Filter to only include non-disabled fields
        active_fields = [field for field in fields if field.get('disabled', True) is False]
        
        if not active_fields:
            logger.warning("No active documentation fields found. Including disabled fields.")
            active_fields = fields
        
        # Create a lookup dictionary for faster matching
        field_lookup = {}
        for field in active_fields:
            name = field.get('name', '')
            normalized_name = normalize_name(name)
            field_lookup[normalized_name] = field
        
        return active_fields, field_lookup
    except Exception as e:
        logger.error(f"Error retrieving documentation fields: {str(e)}")
        return None, None

def load_custom_mapping(file_path, logger):
    """Load custom tag to field mapping from JSON file"""
    if not file_path:
        return None
    
    try:
        with open(file_path, 'r') as f:
            mapping = json.load(f)
        
        if not isinstance(mapping, dict):
            logger.error("Custom mapping file must contain a JSON object (dictionary)")
            return None
        
        logger.info(f"Loaded custom mapping with {len(mapping)} entries")
        return mapping
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error loading custom mapping file: {str(e)}")
        return None

def check_policy_count(ip, domain_id, device_id, session, logger):
    """Check if device has any policies"""
    query = f"domain {{id={domain_id}}} AND device {{id={device_id}}} AND policy {{policyType = 'SECURITY' AND parentId is null}}"
    url = f"https://{ip}/securitymanager/api/siql/policy/paged-search"
    
    params = {
        "q": query,
        "page": 0,
        "pageSize": 1
    }
    
    try:
        response = session.get(url, params=params)
        if response.status_code != 200:
            logger.error(f"Failed to check policies: {response.status_code} - {response.text}")
            return 0
        
        data = response.json()
        return data.get("total", 0)
    except Exception as e:
        logger.error(f"Error checking policies: {str(e)}")
        return 0

def select_device(ip, domain_id, session, logger, device_id=None, show_all=False, non_interactive=False):
    """Allow user to select a device or use provided device ID"""
    if device_id:
        # Verify the device exists and has policies
        policy_count = check_policy_count(ip, domain_id, device_id, session, logger)
        if policy_count > 0:
            logger.info(f"Using provided device ID: {device_id} ({policy_count} policies)")
            return device_id
        elif show_all or non_interactive:
            logger.warning(f"Device ID {device_id} has no policies, but proceeding as requested.")
            return device_id
        else:
            logger.warning(f"Device ID {device_id} has no policies. Please select a different device.")
            device_id = None
    
    # In non-interactive mode, we can't proceed without a device
    if non_interactive:
        logger.error("No valid device ID provided in non-interactive mode")
        sys.exit(1)
    
    # Pagination setup
    page_size = 20  # 20 devices per page
    current_page = 0
    total_devices = None
    
    while True:
        # Fetch devices (paginated)
        logger.info(f"Fetching devices (Page {current_page + 1})...")
        device_url = f"https://{ip}/securitymanager/api/domain/{domain_id}/device?page={current_page}&pageSize={page_size}"
        
        try:
            device_response = session.get(device_url)
            
            if device_response.status_code == 200:
                devices = device_response.json().get('results', [])
                total_devices = device_response.json().get('total', 0)
                
                if not devices:
                    logger.error("No devices found.")
                    sys.exit(1)
                
                # Get policy counts for each device if not showing all
                if not show_all:
                    for device in devices:
                        device['policyCount'] = check_policy_count(ip, domain_id, device['id'], session, logger)
                
                # Filter devices with policies
                filtered_devices = devices if show_all else [d for d in devices if d.get('policyCount', 0) > 0]
                
                if not filtered_devices and not show_all:
                    logger.warning(f"No devices with policies found on page {current_page + 1}.")
                    if current_page > 0:
                        current_page -= 1
                        continue
                
                # Display the devices
                print("\nAvailable Devices (Page", current_page + 1, "):")
                print("ID    | Name                           | Policies")
                print("------|--------------------------------|---------")
                
                for device in filtered_devices:
                    device_id = device.get('id', 'N/A')
                    name = device.get('name', 'Unnamed')[:30]  # Truncate long names
                    policy_count = device.get('policyCount', 'N/A') if not show_all else '?'
                    
                    print(f"{device_id:<6} | {name:<30} | {policy_count}")
                
                # Pagination controls
                action = input("\nSelect a device by ID, or type 'n' for next page, 'p' for previous page: ").strip()
                
                if action.lower() == 'n':
                    if (current_page + 1) * page_size >= total_devices:
                        print("You are already on the last page.")
                    else:
                        current_page += 1
                elif action.lower() == 'p':
                    if current_page == 0:
                        print("You are already on the first page.")
                    else:
                        current_page -= 1
                elif action.isdigit():
                    selected_id = int(action)
                    for device in devices:
                        if device['id'] == selected_id:
                            policy_count = device.get('policyCount', 0) if not show_all else check_policy_count(ip, domain_id, selected_id, session, logger)
                            
                            if policy_count > 0 or show_all:
                                logger.info(f"Selected Device: {device.get('name')} (ID: {selected_id}, Policies: {policy_count})")
                                return selected_id
                            else:
                                print(f"Device {device.get('name')} has no policies. Please select a different device.")
                    
                    print("Invalid device ID. Please enter a valid device ID from the list.")
                else:
                    print("Invalid input. Please enter a valid device ID or 'n'/'p' for navigation.")
            else:
                logger.error(f"Failed to retrieve devices. Status code: {device_response.status_code}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error retrieving devices: {str(e)}")
            sys.exit(1)

def get_all_nsg_policies(ip, domain_id, device_id, session, logger, page_size=100):
    """Get all NSG policies from FireMon with pagination"""
    query = f"domain {{id={domain_id}}} AND device {{id={device_id}}} AND policy {{policyType = 'SECURITY' AND parentId is null}}"
    url = f"https://{ip}/securitymanager/api/siql/policy/paged-search"
    
    all_results = []
    page = 0
    total_pages = 1  # Will be updated after first request
    
    while page < total_pages:
        params = {
            "q": query,
            "page": page,
            "pageSize": page_size,
            "sort": "displayName"
        }
        
        try:
            response = session.get(url, params=params)
            if response.status_code != 200:
                logger.error(f"Failed to get NSG policies: {response.status_code} - {response.text}")
                sys.exit(1)
            
            data = response.json()
            all_results.extend(data.get("results", []))
            
            total = data.get("total", 0)
            total_pages = (total + page_size - 1) // page_size
            
            logger.info(f"Retrieved page {page + 1} of {total_pages} ({len(data.get('results', []))} policies)")
            page += 1
        except Exception as e:
            logger.error(f"Error retrieving policies: {str(e)}")
            sys.exit(1)
    
    return all_results

def map_tags_to_doc_fields(tags, field_lookup, custom_mapping=None, ignore_case=False, logger=None):
    """Map NSG tags to FireMon documentation fields"""
    doc_field_updates = []
    
    for tag in tags:
        tag_name = tag.get('name', 'Unknown')
        tag_value = tag.get('value', '')
        
        # Skip empty values
        if not tag_value:
            continue
        
        # Check custom mapping first
        mapped_field_name = None
        if custom_mapping and tag_name in custom_mapping:
            mapped_field_name = custom_mapping[tag_name]
            if logger:
                logger.debug(f"Using custom mapping: {tag_name} -> {mapped_field_name}")
        
        # Normalize the tag name for matching
        normalized_tag_name = normalize_name(tag_name)
        
        # Look for matching documentation field
        target_field = None
        
        if mapped_field_name:
            # Look for the mapped field name
            normalized_mapped = normalize_name(mapped_field_name)
            if normalized_mapped in field_lookup:
                target_field = field_lookup[normalized_mapped]
        else:
            # Try direct match
            if normalized_tag_name in field_lookup:
                target_field = field_lookup[normalized_tag_name]
            # If ignoring case, we already normalized to lowercase
            elif ignore_case:
                # Try to find a close match
                for field_name, field in field_lookup.items():
                    if field_name in normalized_tag_name or normalized_tag_name in field_name:
                        target_field = field
                        break
        
        if target_field:
            field_id = target_field.get('id')
            if field_id:
                doc_field_updates.append({
                    "action": "REPLACE",
                    "id": field_id,
                    "value": tag_value
                })
                if logger:
                    logger.debug(f"Mapped '{tag_name}' to '{target_field.get('name')}' with value '{tag_value}'")
        elif logger:
            logger.debug(f"No matching documentation field found for tag '{tag_name}'")
    
    return doc_field_updates

def update_rule_documentation_bulk(ip, domain_id, device_id, policy_match_ids, field_updates, session, logger, dry_run=False):
    """Update multiple rule documentation fields for policies"""
    if not policy_match_ids or not field_updates:
        logger.warning("No policy match IDs or field updates provided. Nothing to update.")
        return True
    
    if dry_run:
        logger.info(f"DRY RUN: Would update {len(field_updates)} documentation fields for {len(policy_match_ids)} policies")
        for update in field_updates:
            logger.debug(f"  Field ID {update['id']}: {update['value']}")
        return True
    
    url = f"https://{ip}/securitymanager/api/domain/{domain_id}/ruledoc/bulk"
    
    # Create SIQL query for the policies
    policy_conditions = " OR ".join([f"uid = '{match_id}'" for match_id in policy_match_ids])
    siql = f"policy {{ ({policy_conditions}) }}"
    
    payload = {
        "deleteExpirationDate": False,
        "props": field_updates,
        "siql": siql,
        "deviceId": str(device_id)
    }
    
    try:
        response = session.put(url, json=payload)
        if response.status_code not in [200, 201, 204]:
            logger.error(f"Failed to update rule documentation: {response.status_code} - {response.text}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Error updating rule documentation: {str(e)}")
        return False

def main():
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    logger = setup_logging(
        verbose=args.verbose,
        log_file=args.log_file,
        log_max_size=args.log_max_size,
        log_backup_count=args.log_backup_count
    )
    
    try:
        # Load custom mapping if provided
        custom_mapping = None
        if args.tag_map:
            custom_mapping = load_custom_mapping(args.tag_map, logger)
        
        # Authenticate with FireMon
        session = authenticate_session(args.ip, args.username, args.password, logger)
        
        # Get documentation fields and create lookup
        logger.info(f"Retrieving available documentation fields from domain {args.domain}")
        doc_fields, field_lookup = get_documentation_fields(args.ip, args.domain, session, logger)
        
        if not doc_fields:
            logger.error("Failed to retrieve documentation fields. Exiting.")
            sys.exit(1)
        
        # Display available fields and ask for confirmation only in interactive mode
        if not args.non_interactive:
            print("\nAvailable Documentation Fields for Mapping:")
            print("ID    | Name                           | Type")
            print("------|--------------------------------|--------")
            
            for field in doc_fields:
                field_id = field.get('id', 'N/A')
                name = field.get('name', 'Unknown')[:30]  # Truncate long names
                field_type = field.get('type', 'Unknown')[:15]
                
                print(f"{field_id:<6} | {name:<30} | {field_type}")
            
            # Allow user to confirm
            if input("\nContinue with mapping NSG tags to these fields? (y/n): ").lower() != 'y':
                logger.info("Operation cancelled by user.")
                sys.exit(0)
        
        # Select device if not provided
        if not args.device:
            args.device = select_device(args.ip, args.domain, session, logger, 
                                        show_all=args.show_all_devices,
                                        non_interactive=args.non_interactive)
        else:
            # Verify device has policies
            policy_count = check_policy_count(args.ip, args.domain, args.device, session, logger)
            if policy_count == 0 and not args.show_all_devices and not args.non_interactive:
                logger.warning(f"Device ID {args.device} has no policies.")
                if input("Continue anyway? (y/n): ").lower() != 'y':
                    args.device = select_device(args.ip, args.domain, session, logger, 
                                               show_all=args.show_all_devices,
                                               non_interactive=args.non_interactive)
        
        # Get all NSG policies
        logger.info(f"Retrieving NSG policies from device {args.device} in domain {args.domain}")
        policies = get_all_nsg_policies(args.ip, args.domain, args.device, session, logger)
        logger.info(f"Retrieved {len(policies)} NSG policies")
        
        if not policies:
            logger.warning("No policies found. Nothing to update.")
            sys.exit(0)
        
        # Process policies in batches
        total_policies_updated = 0
        total_fields_updated = 0
        total_skipped = 0
        batch_count = (len(policies) + args.batch_size - 1) // args.batch_size
        
        for i in range(0, len(policies), args.batch_size):
            batch = policies[i:i + args.batch_size]
            batch_num = i // args.batch_size + 1
            logger.info(f"Processing batch {batch_num} of {batch_count}")
            
            for policy in batch:
                # Get tags for the policy
                all_tags = policy.get("objectTags", [])
                policy_name = policy.get("displayName", "Unknown policy")
                
                # Skip if no tags
                if not all_tags:
                    logger.warning(f"No tags found for {policy_name}, skipping")
                    total_skipped += 1
                    continue
                
                # Get child policies (inbound and outbound rules)
                child_policies = policy.get("childPolicies", [])
                
                # Extract match IDs of child policies
                child_match_ids = [child["matchId"] for child in child_policies if "matchId" in child]
                
                if not child_match_ids:
                    logger.warning(f"No child policies found for {policy_name}")
                    total_skipped += 1
                    continue
                
                # Map NSG tags to documentation fields
                field_updates = map_tags_to_doc_fields(
                    all_tags, 
                    field_lookup, 
                    custom_mapping, 
                    args.ignore_case,
                    logger
                )
                
                if not field_updates:
                    logger.warning(f"No mappable tags found for {policy_name}, skipping")
                    total_skipped += 1
                    continue
                
                # Log which tags are being mapped
                logger.info(f"Policy {policy_name}: Mapping {len(field_updates)} fields")
                for update in field_updates:
                    field_id = update['id']
                    field_name = next((f['name'] for f in doc_fields if f['id'] == field_id), f"Field {field_id}")
                    logger.debug(f"  {field_name}: {update['value']}")
                
                try:
                    # Update rule documentation for child policies
                    success = update_rule_documentation_bulk(
                        args.ip, args.domain, args.device, 
                        child_match_ids, field_updates, session, logger,
                        args.dry_run
                    )
                    
                    if success:
                        logger.info(f"Updated documentation for {policy_name} with {len(child_match_ids)} child policies")
                        total_policies_updated += len(child_match_ids)
                        total_fields_updated += len(field_updates) * len(child_match_ids)
                    else:
                        logger.error(f"Failed to update documentation for {policy_name}")
                except Exception as e:
                    logger.error(f"Error updating documentation for {policy_name}: {str(e)}")
            
            # Add a small delay between batches
            if i + args.batch_size < len(policies) and not args.dry_run:
                time.sleep(1)
        
        # Summary
        if args.dry_run:
            logger.info(f"DRY RUN: Would have updated {total_fields_updated} documentation fields across {total_policies_updated} policies")
        else:
            logger.info(f"Successfully updated {total_fields_updated} documentation fields across {total_policies_updated} policies")
        
        if total_skipped > 0:
            logger.info(f"Skipped {total_skipped} policies (no tags, no child policies, or no mappable fields)")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
