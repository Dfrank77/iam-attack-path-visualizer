import matplotlib.pyplot as plt
import json
from datetime import datetime
import textwrap

def wrap_label(text, width=12):
    """Wrap text to fit in node"""
    return '\n'.join(textwrap.wrap(text, width=width, break_long_words=True))

def visualize_attack_paths(graph, output_file='output/attack_paths.png'):
    """Generate clean, hierarchical visualization matching Entra ID style"""
    
    print("\n🎨 Generating privilege escalation visualization...")
    
    import networkx as nx
    
    # Separate nodes by type and privilege level
    users = []
    groups = []
    roles = []
    admin_entities = []
    
    for node, data in graph.nodes(data=True):
        node_type = data.get('type', 'unknown')
        has_admin = data.get('has_admin', False)
        
        if has_admin:
            admin_entities.append(node)
        elif node_type == 'user':
            users.append(node)
        elif node_type == 'group':
            groups.append(node)
        elif node_type == 'role':
            roles.append(node)
    
    # Create figure
    plt.figure(figsize=(28, 18), facecolor='white')  # Made even bigger
    
    # Calculate hierarchical positions
    pos = {}
    
    # Admin entities at TOP (red - critical)
    admin_list = sorted(admin_entities)
    admin_spacing = 2.2  # More spacing
    admin_start_x = -(len(admin_list) - 1) * admin_spacing / 2 if admin_list else 0
    for i, entity in enumerate(admin_list):
        pos[entity] = (admin_start_x + i * admin_spacing, 2.0)
    
    # Roles in UPPER-MIDDLE
    role_list = sorted([r for r in roles if r not in admin_entities])
    role_spacing = 2.0  # More spacing for roles
    role_start_x = -(len(role_list) - 1) * role_spacing / 2 if role_list else 0
    for i, role in enumerate(role_list):
        pos[role] = (role_start_x + i * role_spacing, 1.3)
    
    # Groups in MIDDLE
    group_list = sorted([g for g in groups if g not in admin_entities])
    group_spacing = 1.5
    group_start_x = -(len(group_list) - 1) * group_spacing / 2 if group_list else 0
    for i, group in enumerate(group_list):
        pos[group] = (group_start_x + i * group_spacing, 0.7)
    
    # Users at BOTTOM
    user_list = sorted([u for u in users if u not in admin_entities])
    user_spacing = 1.5
    user_start_x = -(len(user_list) - 1) * user_spacing / 2 if user_list else 0
    for i, user in enumerate(user_list):
        pos[user] = (user_start_x + i * user_spacing, 0.0)
    
    # Draw edges first (behind nodes)
    if graph.edges():
        nx.draw_networkx_edges(
            graph, pos,
            edge_color='#34495e',
            arrows=True,
            arrowsize=25,
            width=2.5,
            arrowstyle='->',
            connectionstyle='arc3,rad=0.1',
            alpha=0.6
        )
    
    # Draw user nodes (blue circles)
    if user_list:
        nx.draw_networkx_nodes(
            graph, pos,
            nodelist=user_list,
            node_color='#3498db',
            node_size=5000,
            node_shape='o',
            edgecolors='#2c3e50',
            linewidths=2
        )
    
    # Draw group nodes (orange squares)
    if group_list:
        nx.draw_networkx_nodes(
            graph, pos,
            nodelist=group_list,
            node_color='#f39c12',
            node_size=5000,
            node_shape='s',
            edgecolors='#d68910',
            linewidths=2
        )
    
    # Draw role nodes (purple pentagons) - MUCH BIGGER
    if role_list:
        nx.draw_networkx_nodes(
            graph, pos,
            nodelist=role_list,
            node_color='#9b59b6',
            node_size=9000,  # Increased from 6500 to 9000
            node_shape='p',
            edgecolors='#8e44ad',
            linewidths=2
        )
    
    # Draw admin nodes (red diamonds - LARGEST)
    if admin_list:
        nx.draw_networkx_nodes(
            graph, pos,
            nodelist=admin_list,
            node_color='#e74c3c',
            node_size=8000,  # Also increased
            node_shape='D',
            edgecolors='#c0392b',
            linewidths=3
        )
    
    # Wrap and draw labels
    wrapped_labels = {}
    for node in graph.nodes():
        node_data = graph.nodes[node]
        has_admin = node_data.get('has_admin', False)
        node_type = node_data.get('type', 'unknown')
        
        # Aggressive wrapping for roles
        if has_admin:
            wrapped_labels[node] = wrap_label(node, width=14)
        elif node_type == 'role':
            wrapped_labels[node] = wrap_label(node, width=12)  # Will break words if needed
        elif node_type == 'group':
            wrapped_labels[node] = wrap_label(node, width=10)
        else:  # user
            wrapped_labels[node] = wrap_label(node, width=10)
    
    nx.draw_networkx_labels(
        graph, pos,
        wrapped_labels,
        font_size=7,  # Smaller font
        font_weight='bold',
        font_color='white',
        font_family='sans-serif'
    )
    
    # Title
    total_entities = len(graph.nodes())
    total_paths = len(graph.edges())
    admin_count = len(admin_entities)
    
    plt.title(
        f'AWS IAM Privilege Escalation Analysis\n'
        f'{total_entities} Entities • {admin_count} Admin Access • {total_paths} Privilege Paths\n'
        f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        fontsize=18,
        fontweight='bold',
        pad=30,
        color='#2c3e50'
    )
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#3498db', edgecolor='#2c3e50', label='Users'),
        Patch(facecolor='#f39c12', edgecolor='#d68910', label='Groups'),
        Patch(facecolor='#9b59b6', edgecolor='#8e44ad', label='Roles'),
        Patch(facecolor='#e74c3c', edgecolor='#c0392b', label='Admin Access')
    ]
    plt.legend(
        handles=legend_elements,
        loc='upper left',
        fontsize=13,
        frameon=True,
        fancybox=True,
        shadow=True
    )
    
    # Findings box
    findings_text = f"⚠️  Admin Entities Found: {admin_count}\n📊  Total Privilege Paths: {total_paths}"
    plt.text(
        0.02, 0.02,
        findings_text,
        transform=plt.gcf().transFigure,
        fontsize=12,
        bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8),
        color='#e74c3c',
        fontweight='bold'
    )
    
    # Remove axes
    plt.axis('off')
    plt.tight_layout()
    
    # Save
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Visualization saved to {output_file}")
    
    return output_file
