"""
AWS IAM Scanner
Scans AWS accounts to identify privilege escalation paths through:
- Role assumption chains
- Cross-account access
- Overprivileged trust policies
"""

import boto3
import json
from typing import Dict, List, Set, Tuple
from colorama import Fore, Style, init

init(autoreset=True)


class AWSIAMScanner:
    """
    Scans AWS IAM configuration to identify privilege escalation paths.
    
    Business Value:
    - Finds "shadow admins" who can escalate to admin through role chains
    - Identifies overly permissive trust policies
    - Maps cross-account privilege escalation risks
    """
    
    # AWS managed policies that grant admin access
    ADMIN_POLICIES = {
        'AdministratorAccess',
        'PowerUserAccess',  # Almost admin
        'IAMFullAccess'     # Can create admins
    }
    
    def __init__(self, profile_name=None, account_id=None):
        """Initialize scanner with AWS credentials"""
        print(f"{Fore.CYAN}🔍 Initializing AWS IAM Scanner...{Style.RESET_ALL}")
        
        # Connect to AWS
        if profile_name:
            self.session = boto3.Session(profile_name=profile_name)
        else:
            self.session = boto3.Session()
        
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        
        # Get current account ID
        if not account_id:
            identity = self.sts.get_caller_identity()
            self.account_id = identity['Account']
        else:
            self.account_id = account_id
        
        print(f"{Fore.GREEN}✓ Connected to AWS Account: {self.account_id}{Style.RESET_ALL}")
        
        # Storage for scan results
        self.users = []
        self.roles = []
        self.groups = []
        self.privilege_paths = []
        self.admin_entities = set()
    
    def scan_all(self) -> Dict:
        """
        Run complete IAM scan.
        
        Returns all data needed to build privilege escalation graph.
        """
        print(f"\n{Fore.CYAN}Starting IAM scan...{Style.RESET_ALL}\n")
        
        # Step 1: Get all IAM entities
        self._scan_users()
        self._scan_roles()
        self._scan_groups()
        
        # Step 2: Identify admin access
        self._identify_admin_entities()
        
        # Step 3: Build privilege paths
        self._build_privilege_paths()
        
        print(f"\n{Fore.GREEN}✓ Scan complete!{Style.RESET_ALL}\n")
        
        return {
            'account_id': self.account_id,
            'users': self.users,
            'roles': self.roles,
            'groups': self.groups,
            'admin_entities': list(self.admin_entities),
            'privilege_paths': self.privilege_paths,
            'summary': {
                'total_users': len(self.users),
                'total_roles': len(self.roles),
                'total_groups': len(self.groups),
                'admin_count': len(self.admin_entities),
                'privilege_paths_found': len(self.privilege_paths)
            }
        }
    
    def _scan_users(self):
        """Get all IAM users and their group memberships"""
        print(f"{Fore.YELLOW}Scanning IAM users...{Style.RESET_ALL}")
        
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_data = {
                        'name': user['UserName'],
                        'arn': user['Arn'],
                        'type': 'user',
                        'groups': [],
                        'policies': []
                    }
                    
                    # Get user's groups
                    try:
                        groups_response = self.iam.list_groups_for_user(UserName=user['UserName'])
                        user_data['groups'] = [g['GroupName'] for g in groups_response['Groups']]
                    except Exception as e:
                        print(f"{Fore.RED}  ⚠ Error getting groups for {user['UserName']}: {str(e)}{Style.RESET_ALL}")
                    
                    # Get user's attached policies
                    try:
                        policies_response = self.iam.list_attached_user_policies(UserName=user['UserName'])
                        user_data['policies'] = [p['PolicyName'] for p in policies_response['AttachedPolicies']]
                    except Exception as e:
                        print(f"{Fore.RED}  ⚠ Error getting policies for {user['UserName']}: {str(e)}{Style.RESET_ALL}")
                    
                    self.users.append(user_data)
            
            print(f"{Fore.GREEN}  ✓ Found {len(self.users)} users{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}✗ Error scanning users: {str(e)}{Style.RESET_ALL}")
    
    def _scan_roles(self):
        """
        Get all IAM roles and their trust policies.
        
        Trust policy = who can assume this role
        This is KEY to finding privilege escalation paths
        """
        print(f"{Fore.YELLOW}Scanning IAM roles...{Style.RESET_ALL}")
        
        try:
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    # Parse trust policy (who can assume this role)
                    trust_policy = role.get('AssumeRolePolicyDocument', {})
                    
                    role_data = {
                        'name': role['RoleName'],
                        'arn': role['Arn'],
                        'type': 'role',
                        'trust_policy': trust_policy,
                        'trusted_entities': self._parse_trust_policy(trust_policy),
                        'policies': []
                    }
                    
                    # Get role's attached policies
                    try:
                        policies_response = self.iam.list_attached_role_policies(RoleName=role['RoleName'])
                        role_data['policies'] = [p['PolicyName'] for p in policies_response['AttachedPolicies']]
                    except Exception as e:
                        print(f"{Fore.RED}  ⚠ Error getting policies for {role['RoleName']}: {str(e)}{Style.RESET_ALL}")
                    
                    self.roles.append(role_data)
            
            print(f"{Fore.GREEN}  ✓ Found {len(self.roles)} roles{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}✗ Error scanning roles: {str(e)}{Style.RESET_ALL}")
    
    def _scan_groups(self):
        """Get all IAM groups and their policies"""
        print(f"{Fore.YELLOW}Scanning IAM groups...{Style.RESET_ALL}")
        
        try:
            paginator = self.iam.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_data = {
                        'name': group['GroupName'],
                        'arn': group['Arn'],
                        'type': 'group',
                        'policies': []
                    }
                    
                    # Get group's attached policies
                    try:
                        policies_response = self.iam.list_attached_group_policies(GroupName=group['GroupName'])
                        group_data['policies'] = [p['PolicyName'] for p in policies_response['AttachedPolicies']]
                    except Exception as e:
                        print(f"{Fore.RED}  ⚠ Error getting policies for {group['GroupName']}: {str(e)}{Style.RESET_ALL}")
                    
                    self.groups.append(group_data)
            
            print(f"{Fore.GREEN}  ✓ Found {len(self.groups)} groups{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}✗ Error scanning groups: {str(e)}{Style.RESET_ALL}")
    
    def _parse_trust_policy(self, trust_policy: Dict) -> List[str]:
        """
        Extract who can assume this role from the trust policy.
        
        This is CRITICAL for finding privilege escalation:
        - If a role trusts another role, that's a chain link
        - If a role trusts root (*), that's dangerous
        """
        trusted = []
        
        try:
            for statement in trust_policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    # AWS account principals
                    if 'AWS' in principal:
                        aws_principals = principal['AWS']
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        trusted.extend(aws_principals)
                    
                    # Service principals (e.g., ec2.amazonaws.com)
                    if 'Service' in principal:
                        services = principal['Service']
                        if isinstance(services, str):
                            services = [services]
                        trusted.extend(services)
        
        except Exception as e:
            print(f"{Fore.RED}  ⚠ Error parsing trust policy: {str(e)}{Style.RESET_ALL}")
        
        return trusted
    
    def _identify_admin_entities(self):
        """
        Find all entities (users, roles, groups) with admin access.
        
        Admin access = can do anything in AWS
        These are the "target" nodes in our attack graph
        """
        print(f"{Fore.YELLOW}Identifying admin entities...{Style.RESET_ALL}")
        
        # Check users
        for user in self.users:
            if any(policy in self.ADMIN_POLICIES for policy in user['policies']):
                self.admin_entities.add(user['name'])
        
        # Check roles
        for role in self.roles:
            if any(policy in self.ADMIN_POLICIES for policy in role['policies']):
                self.admin_entities.add(role['name'])
        
        # Check groups
        for group in self.groups:
            if any(policy in self.ADMIN_POLICIES for policy in group['policies']):
                self.admin_entities.add(group['name'])
        
        print(f"{Fore.GREEN}  ✓ Found {len(self.admin_entities)} admin entities{Style.RESET_ALL}")
    
    def _build_privilege_paths(self):
        """
        Build privilege escalation paths.
        
        Shows: User → Group → Role → Admin Role
        
        This is what hiring managers want to see!
        """
        print(f"{Fore.YELLOW}Building privilege escalation paths...{Style.RESET_ALL}")
        
        # User → Group paths
        for user in self.users:
            for group_name in user['groups']:
                if group_name in self.admin_entities:
                    self.privilege_paths.append({
                        'type': 'user_to_group_admin',
                        'path': [user['name'], group_name],
                        'risk': 'HIGH',
                        'description': f"User {user['name']} has admin through group {group_name}"
                    })
        
        # Role assumption chains
        for role in self.roles:
            if role['name'] in self.admin_entities:
                for trusted in role['trusted_entities']:
                    # Check if trusted entity is a role in this account
                    trusted_role_name = self._extract_role_name(trusted)
                    if trusted_role_name:
                        self.privilege_paths.append({
                            'type': 'role_chain_admin',
                            'path': [trusted_role_name, role['name']],
                            'risk': 'CRITICAL',
                            'description': f"Role {trusted_role_name} can assume admin role {role['name']}"
                        })
        
        print(f"{Fore.GREEN}  ✓ Found {len(self.privilege_paths)} privilege escalation paths{Style.RESET_ALL}")
    
    def _extract_role_name(self, arn_or_principal: str) -> str:
        """Extract role name from ARN or principal"""
        if ':role/' in arn_or_principal:
            return arn_or_principal.split(':role/')[-1]
        return None


def main():
    """Test the scanner"""
    scanner = AWSIAMScanner()
    results = scanner.scan_all()
    
    print(f"\n{Fore.CYAN}=== SCAN RESULTS ==={Style.RESET_ALL}")
    print(json.dumps(results['summary'], indent=2))
    
    if results['privilege_paths']:
        print(f"\n{Fore.RED}⚠ PRIVILEGE ESCALATION PATHS FOUND:{Style.RESET_ALL}")
        for path in results['privilege_paths']:
            print(f"  {path['risk']}: {path['description']}")


if __name__ == '__main__':
    main()