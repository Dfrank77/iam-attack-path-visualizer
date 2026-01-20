"""
Graph Builder
Builds NetworkX graph from AWS IAM scan data
"""

import networkx as nx
from typing import Dict

def build_privilege_graph(scanner_data: Dict) -> nx.DiGraph:
    """
    Build directed graph showing privilege escalation paths
    
    Args:
        scanner_data: Dictionary from AWSIAMScanner.scan_all()
        
    Returns:
        NetworkX DiGraph with privilege relationships
    """
    
    print("📊 Building privilege escalation graph...")
    
    G = nx.DiGraph()
    
    # Extract data from scanner (using correct keys!)
    users = scanner_data.get('users', [])
    groups = scanner_data.get('groups', [])
    roles = scanner_data.get('roles', [])
    admin_entities = scanner_data.get('admin_entities', [])
    privilege_paths = scanner_data.get('privilege_paths', [])
    
    # Add user nodes
    for user in users:
        user_name = user.get('name', 'Unknown')
        has_admin = user_name in admin_entities
        
        G.add_node(
            user_name,
            type='user',
            has_admin=has_admin,
            arn=user.get('arn', '')
        )
        
        # Add edges for group memberships
        for group_name in user.get('groups', []):
            G.add_edge(user_name, group_name, relationship='member_of')
    
    # Add group nodes
    for group in groups:
        group_name = group.get('name', 'Unknown')
        has_admin = group_name in admin_entities
        
        G.add_node(
            group_name,
            type='group',
            has_admin=has_admin,
            arn=group.get('arn', '')
        )
    
    # Add role nodes
    for role in roles:
        role_name = role.get('name', 'Unknown')
        has_admin = role_name in admin_entities
        
        G.add_node(
            role_name,
            type='role',
            has_admin=has_admin,
            arn=role.get('arn', '')
        )
    
    # Add edges from privilege paths
    for path in privilege_paths:
        path_steps = path.get('path', [])
        if len(path_steps) >= 2:
            # Add edges between consecutive steps
            for i in range(len(path_steps) - 1):
                source = path_steps[i]
                target = path_steps[i + 1]
                G.add_edge(source, target, relationship='privilege_escalation')
    
    print(f"✅ Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    
    return G
