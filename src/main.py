#!/usr/bin/env python3
"""
AWS IAM Attack Path Visualizer
Main execution script
"""

import sys
from aws_scanner import AWSIAMScanner
from graph_builder import build_privilege_graph
from visualizer import visualize_attack_paths

def main():
    print("\n" + "="*60)
    print("  AWS IAM PRIVILEGE ESCALATION ANALYZER")
    print("="*60 + "\n")
    
    # Step 1: Scan AWS IAM environment
    print("🔍 Step 1: Scanning AWS IAM environment...")
    
    try:
        scanner = AWSIAMScanner()
        iam_data = scanner.scan_all()  # This is the correct method!
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    if not iam_data:
        print("❌ No IAM data found. Exiting.")
        sys.exit(1)
    
    # Step 2: Build privilege graph
    print("\n📊 Step 2: Building privilege escalation graph...")
    graph = build_privilege_graph(iam_data)
    
    # Step 3: Generate visualization
    print("\n🎨 Step 3: Generating visualization...")
    output_file = visualize_attack_paths(graph)
    
    # Summary
    print("\n" + "="*60)
    print("  ANALYSIS COMPLETE")
    print("="*60)
    print(f"\n✅ Visualization saved to: {output_file}")
    print(f"✅ Graph contains: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print("\nOpen the visualization to see privilege escalation paths!\n")

if __name__ == "__main__":
    main()
