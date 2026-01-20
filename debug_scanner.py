from src.aws_scanner import AWSIAMScanner
import json

scanner = AWSIAMScanner()
data = scanner.scan_all()

# Print the structure
print("\n=== SCANNER OUTPUT STRUCTURE ===\n")
print("Keys:", data.keys())
print("\n=== SAMPLE DATA ===\n")
for key, value in data.items():
    if isinstance(value, list):
        print(f"{key}: {len(value)} items")
        if value:
            print(f"  Sample: {value[0]}")
    else:
        print(f"{key}: {value}")
