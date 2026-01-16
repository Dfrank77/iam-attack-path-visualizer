"""
IAM Attack Path Visualizer
Creates visual graphs showing privilege escalation paths
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from typing import Dict, List
import json
from datetime import datetime
from colorama import Fore, Style


class IAMVisualizer:
    """
    Creates visual representations of privilege escalation paths.
    
    Generates a graph showing:
    - Users as circles
    - Groups as squares
    - Roles as diamonds
    - Admin entities in RED
    - Normal entities in GREEN
    - Arrows showing "can become" relationships
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()  # Directed graph (arrows have direction)
        
        # Color scheme
        self.colors = {
            'admin': '#FF4444',      # Red - DANGER
            'high_privilege': '#FFA500',  # Orange - WARNING
            'normal': '#90EE90',     # Light green - SAFE
            'user': '#87CEEB',       # Sky blue
            'group': '#DDA0DD',      # Plum
            'role': '#F0E68C'        # Khaki
        }
    
    def create_graph(self, scan_data: Dict):
        """
        Build the privilege escalation graph from scan data.
        
        Nodes = IAM entities (users, roles, groups)
        Edges = privilege escalation paths (who can become what)
        """
        print(f"{Fore.CYAN}Building privilege escalation graph...{Style.RESET_ALL}")
        
        admin_entities = set(scan_data['admin_entities'])
        
        # Add all users as nodes
        for user in scan_data['users']:
            node_color = self.colors['admin'] if user['name'] in admin_entities else self.colors['user']
            self.graph.add_node(
                user['name'],
                node_type='user',
                color=node_color,
                is_admin=user['name'] in admin_entities
            )
            
            # Add edges to groups
            for group in user['groups']:
                self.graph.add_edge(user['name'], group, relationship='member_of')
        
        # Add all groups as nodes
        for group in scan_data['groups']:
            node_color = self.colors['admin'] if group['name'] in admin_entities else self.colors['group']
            self.graph.add_node(
                group['name'],
                node_type='group',
                color=node_color,
                is_admin=group['name'] in admin_entities
            )
        
        # Add all roles as nodes
        for role in scan_data['roles']:
            node_color = self.colors['admin'] if role['name'] in admin_entities else self.colors['role']
            self.graph.add_node(
                role['name'],
                node_type='role',
                color=node_color,
                is_admin=role['name'] in admin_entities
            )
            
            # Add edges for role assumptions
            for trusted in role['trusted_entities']:
                # Extract role name if it's an ARN
                if ':role/' in trusted:
                    trusted_role = trusted.split(':role/')[-1]
                    if self.graph.has_node(trusted_role):
                        self.graph.add_edge(trusted_role, role['name'], relationship='can_assume')
        
        print(f"{Fore.GREEN}✓ Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges{Style.RESET_ALL}")
    
    def visualize(self, output_path: str = 'output/attack_paths.png', title: str = None):
        """
        Create the visual graph image.
        
        This is THE screenshot that gets you hired.
        """
        print(f"{Fore.CYAN}Generating visualization...{Style.RESET_ALL}")
        
        # Create figure
        plt.figure(figsize=(20, 14))
        
        # Layout algorithm - spreads nodes nicely
        pos = nx.spring_layout(self.graph, k=2, iterations=50, seed=42)
        
        # Get node colors
        node_colors = [self.graph.nodes[node].get('color', self.colors['normal']) 
                      for node in self.graph.nodes()]
        
        # Get node shapes based on type
        users = [node for node in self.graph.nodes() 
                if self.graph.nodes[node].get('node_type') == 'user']
        groups = [node for node in self.graph.nodes() 
                 if self.graph.nodes[node].get('node_type') == 'group']
        roles = [node for node in self.graph.nodes() 
                if self.graph.nodes[node].get('node_type') == 'role']
        
        # Draw nodes by type (different shapes)
        if users:
            user_colors = [self.graph.nodes[node]['color'] for node in users]
            nx.draw_networkx_nodes(self.graph, pos, nodelist=users,
                                  node_color=user_colors, node_shape='o',
                                  node_size=3000, alpha=0.9, linewidths=2,
                                  edgecolors='black')
        
        if groups:
            group_colors = [self.graph.nodes[node]['color'] for node in groups]
            nx.draw_networkx_nodes(self.graph, pos, nodelist=groups,
                                  node_color=group_colors, node_shape='s',
                                  node_size=3000, alpha=0.9, linewidths=2,
                                  edgecolors='black')
        
        if roles:
            role_colors = [self.graph.nodes[node]['color'] for node in roles]
            nx.draw_networkx_nodes(self.graph, pos, nodelist=roles,
                                  node_color=role_colors, node_shape='d',
                                  node_size=3000, alpha=0.9, linewidths=2,
                                  edgecolors='black')
        
        # Draw edges (arrows showing privilege escalation)
        nx.draw_networkx_edges(self.graph, pos, width=2, alpha=0.6,
                              edge_color='#555555', arrows=True,
                              arrowsize=20, arrowstyle='->')
        
        # Draw labels
        nx.draw_networkx_labels(self.graph, pos, font_size=10,
                               font_weight='bold', font_color='black')
        
        # Title
        if not title:
            title = f'IAM Privilege Escalation Paths - {datetime.now().strftime("%Y-%m-%d")}'
        plt.title(title, fontsize=20, fontweight='bold', pad=20)
        
        # Legend
        legend_elements = [
            mpatches.Patch(color=self.colors['admin'], label='Admin Access (HIGH RISK)'),
            mpatches.Patch(color=self.colors['user'], label='IAM Users'),
            mpatches.Patch(color=self.colors['group'], label='IAM Groups'),
            mpatches.Patch(color=self.colors['role'], label='IAM Roles'),
            mpatches.FancyArrow(0, 0, 1, 0, color='#555555', label='Privilege Escalation Path')
        ]
        plt.legend(handles=legend_elements, loc='upper left', fontsize=12)
        
        # Remove axes
        plt.axis('off')
        
        # Tight layout
        plt.tight_layout()
        
        # Save
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"{Fore.GREEN}✓ Visualization saved: {output_path}{Style.RESET_ALL}")
        
        return output_path
    
    def generate_report(self, scan_data: Dict, output_path: str = 'output/report.json'):
        """Save detailed findings to JSON"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'account_id': scan_data['account_id'],
            'summary': scan_data['summary'],
            'admin_entities': scan_data['admin_entities'],
            'privilege_paths': scan_data['privilege_paths'],
            'risk_assessment': self._assess_risk(scan_data)
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Fore.GREEN}✓ Report saved: {output_path}{Style.RESET_ALL}")
        
        return output_path
    
    def _assess_risk(self, scan_data: Dict) -> Dict:
        """Calculate risk metrics"""
        total_entities = (scan_data['summary']['total_users'] +
                         scan_data['summary']['total_roles'] +
                         scan_data['summary']['total_groups'])
        
        admin_percentage = (scan_data['summary']['admin_count'] / total_entities * 100) if total_entities > 0 else 0
        
        risk_level = 'LOW'
        if admin_percentage > 30:
            risk_level = 'CRITICAL'
        elif admin_percentage > 15:
            risk_level = 'HIGH'
        elif admin_percentage > 5:
            risk_level = 'MEDIUM'
        
        return {
            'risk_level': risk_level,
            'admin_percentage': round(admin_percentage, 2),
            'findings': len(scan_data['privilege_paths']),
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get remediation recommendation"""
        recommendations = {
            'CRITICAL': 'Immediate action required: Too many admin accounts. Review and remove unnecessary admin access.',
            'HIGH': 'Review admin access assignments. Implement least privilege principles.',
            'MEDIUM': 'Consider access reviews for admin accounts. Document justification for admin access.',
            'LOW': 'Current admin access levels are reasonable. Continue periodic reviews.'
        }
        return recommendations.get(risk_level, '')


def main():
    """Test visualizer with sample data"""
    from aws_scanner import AWSIAMScanner
    
    # Run scan
    scanner = AWSIAMScanner()
    scan_data = scanner.scan_all()
    
    # Create visualizer
    viz = IAMVisualizer()
    viz.create_graph(scan_data)
    viz.visualize()
    viz.generate_report(scan_data)
    
    print(f"\n{Fore.GREEN}✓ Complete! Check output/ folder for results.{Style.RESET_ALL}")


if __name__ == '__main__':
    main()