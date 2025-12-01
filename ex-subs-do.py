import tldextract
import sys
import chardet

def detect_encoding(filename):
    """Detect file encoding"""
    with open(filename, 'rb') as file:
        raw_data = file.read(100000)  # Read first 100KB for detection
        result = chardet.detect(raw_data)
        return result.get('encoding', 'utf-8')

def extract_domains(filename):
    """
    Extract both root domains and subdomains from a file.
    Returns two sets: root domains and full domains (with subdomains)
    """
    try:
        # Try to detect encoding
        encoding = detect_encoding(filename)
        print(f"Detected encoding: {encoding}", file=sys.stderr)
        
        with open(filename, 'r', encoding=encoding, errors='replace') as file:
            lines = file.read().splitlines()
        
        root_domains = set()
        subdomains = set()
        full_domains = set()  # All domains including subdomains
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Clean the line - remove common noise
            line = line.split()[0] if line.split() else line  # Take first word if space separated
            
            # Remove protocol if present
            if line.startswith(('http://', 'https://')):
                line = line.split('://')[1]
            
            # Remove path, query strings, and ports
            line = line.split('/')[0].split('?')[0].split(':')[0]
            
            # Skip if line is empty after cleaning
            if not line:
                continue
            
            # Use tldextract to properly parse domain
            extracted = tldextract.extract(line)
            
            # Skip if no domain or suffix found
            if not extracted.domain or not extracted.suffix:
                continue
            
            # Reconstruct root domain (domain + suffix)
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            root_domains.add(root_domain)
            
            # Add full domain (with subdomain if present)
            if extracted.subdomain:
                full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                subdomains.add(full_domain)
            else:
                full_domain = root_domain
            
            full_domains.add(full_domain)
        
        return root_domains, subdomains, full_domains
            
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def print_results(root_domains, subdomains, full_domains, output_format='separate'):
    """
    Print results in different formats
    output_format options:
    - 'separate': Print root domains and subdomains separately
    - 'combined': Print all domains together
    - 'both': Print both separated and combined
    """
    
    if output_format in ['separate', 'both']:
        print("\n=== ROOT DOMAINS ===", file=sys.stderr)
        print(f"Count: {len(root_domains)}", file=sys.stderr)
        print("=" * 20, file=sys.stderr)
        for domain in sorted(root_domains):
            print(domain)
        
        if subdomains:
            print("\n=== SUBDOMAINS ===", file=sys.stderr)
            print(f"Count: {len(subdomains)}", file=sys.stderr)
            print("=" * 20, file=sys.stderr)
            for domain in sorted(subdomains):
                print(domain)
    
    if output_format in ['combined', 'both']:
        if output_format == 'both':
            print("\n=== ALL DOMAINS (COMBINED) ===", file=sys.stderr)
        print(f"Total unique domains: {len(full_domains)}", file=sys.stderr)
        print("=" * 30, file=sys.stderr)
        for domain in sorted(full_domains):
            print(domain)

def export_to_files(root_domains, subdomains, full_domains, basename):
    """Export results to separate files"""
    import os
    
    # Create output directory if it doesn't exist
    output_dir = "extracted_domains"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save root domains
    with open(os.path.join(output_dir, f"{basename}_roots.txt"), 'w') as f:
        for domain in sorted(root_domains):
            f.write(f"{domain}\n")
    
    # Save subdomains
    if subdomains:
        with open(os.path.join(output_dir, f"{basename}_subdomains.txt"), 'w') as f:
            for domain in sorted(subdomains):
                f.write(f"{domain}\n")
    
    # Save all domains
    with open(os.path.join(output_dir, f"{basename}_all.txt"), 'w') as f:
        for domain in sorted(full_domains):
            f.write(f"{domain}\n")
    
    print(f"\nResults saved to '{output_dir}/' directory", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_domains.py <filename> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print("  --format FORMAT  Output format: separate, combined, both (default: separate)", file=sys.stderr)
        print("  --export         Export results to files", file=sys.stderr)
        print("  --stats          Show statistics only", file=sys.stderr)
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Parse command line options
    output_format = 'separate'
    export_files = False
    stats_only = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--format' and i + 1 < len(sys.argv):
            output_format = sys.argv[i + 1]
            if output_format not in ['separate', 'combined', 'both']:
                print(f"Warning: Invalid format '{output_format}', using 'separate'", file=sys.stderr)
                output_format = 'separate'
            i += 2
        elif sys.argv[i] == '--export':
            export_files = True
            i += 1
        elif sys.argv[i] == '--stats':
            stats_only = True
            i += 1
        else:
            print(f"Warning: Unknown option '{sys.argv[i]}'", file=sys.stderr)
            i += 1
    
    # Extract domains
    root_domains, subdomains, full_domains = extract_domains(filename)
    
    # Show statistics
    print(f"\n=== STATISTICS ===", file=sys.stderr)
    print(f"Root domains found: {len(root_domains)}", file=sys.stderr)
    print(f"Subdomains found: {len(subdomains)}", file=sys.stderr)
    print(f"Total unique domains: {len(full_domains)}", file=sys.stderr)
    
    if stats_only:
        sys.exit(0)
    
    # Print results
    print_results(root_domains, subdomains, full_domains, output_format)
    
    # Export to files if requested
    if export_files:
        import os
        basename = os.path.splitext(os.path.basename(filename))[0]
        export_to_files(root_domains, subdomains, full_domains, basename)
