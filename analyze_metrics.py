#!/usr/bin/env python3
"""
STAS Source Code Metrics Analyzer
Generates comprehensive metrics for all source files in the project.
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime

def count_lines(file_path):
    """Count various types of lines in a source file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        total_lines = len(lines)
        
        # Count different types of lines
        blank_lines = 0
        comment_lines = 0
        code_lines = 0
        
        in_block_comment = False
        
        for line in lines:
            stripped = line.strip()
            
            # Empty lines
            if not stripped:
                blank_lines += 1
                continue
            
            # Handle C-style block comments
            if file_path.suffix in ['.c', '.h']:
                # Check for block comment start/end
                if '/*' in stripped and '*/' in stripped and stripped.index('/*') < stripped.index('*/'):
                    # Single line block comment
                    comment_lines += 1
                    continue
                elif '/*' in stripped:
                    in_block_comment = True
                    comment_lines += 1
                    continue
                elif '*/' in stripped:
                    in_block_comment = False
                    comment_lines += 1
                    continue
                elif in_block_comment:
                    comment_lines += 1
                    continue
                elif stripped.startswith('//'):
                    comment_lines += 1
                    continue
            
            # Handle Python comments
            elif file_path.suffix == '.py':
                if stripped.startswith('#'):
                    comment_lines += 1
                    continue
                # Handle triple-quoted strings (docstrings)
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    comment_lines += 1
                    continue
            
            # Handle Makefile comments
            elif file_path.name == 'Makefile' or file_path.suffix == '.mk':
                if stripped.startswith('#'):
                    comment_lines += 1
                    continue
            
            # Handle assembly comments
            elif file_path.suffix in ['.s', '.S', '.asm']:
                if stripped.startswith(';') or stripped.startswith('#'):
                    comment_lines += 1
                    continue
            
            # If we get here, it's a code line
            code_lines += 1
        
        return {
            'total_lines': total_lines,
            'blank_lines': blank_lines,
            'comment_lines': comment_lines,
            'code_lines': code_lines
        }
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return {'total_lines': 0, 'blank_lines': 0, 'comment_lines': 0, 'code_lines': 0}

def get_file_size(file_path):
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except:
        return 0

def analyze_complexity(file_path):
    """Basic complexity analysis."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Count functions (C/C++ style)
        if file_path.suffix in ['.c', '.h']:
            # Simple function counting - look for pattern: type name(
            functions = len(re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*{', content))
            # Count if statements
            ifs = len(re.findall(r'\bif\s*\(', content))
            # Count for/while loops
            loops = len(re.findall(r'\b(for|while)\s*\(', content))
            # Count switch statements
            switches = len(re.findall(r'\bswitch\s*\(', content))
            
        elif file_path.suffix == '.py':
            functions = len(re.findall(r'^\s*def\s+\w+', content, re.MULTILINE))
            ifs = len(re.findall(r'\bif\s+', content))
            loops = len(re.findall(r'\b(for|while)\s+', content))
            switches = 0  # Python doesn't have switch
            
        else:
            functions = 0
            ifs = 0
            loops = 0
            switches = 0
        
        cyclomatic_complexity = 1 + ifs + loops + switches  # Basic McCabe complexity
        
        return {
            'functions': functions,
            'if_statements': ifs,
            'loops': loops,
            'switches': switches,
            'cyclomatic_complexity': cyclomatic_complexity
        }
    
    except Exception as e:
        return {'functions': 0, 'if_statements': 0, 'loops': 0, 'switches': 0, 'cyclomatic_complexity': 1}

def get_file_type(file_path):
    """Determine file type based on extension."""
    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    
    if ext in ['.c']:
        return 'C Source'
    elif ext in ['.h']:
        return 'C Header'
    elif ext in ['.py']:
        return 'Python'
    elif ext in ['.s', '.S']:
        return 'Assembly'
    elif ext in ['.md']:
        return 'Markdown'
    elif name == 'makefile' or ext == '.mk':
        return 'Makefile'
    elif ext in ['.txt']:
        return 'Text'
    elif ext in ['.json']:
        return 'JSON'
    elif ext in ['.sh']:
        return 'Shell Script'
    elif ext in ['.inc']:
        return 'Include'
    else:
        return 'Other'

def scan_directory(root_path):
    """Scan directory for source files and analyze them."""
    results = []
    
    # Define which files to include
    include_extensions = {'.c', '.h', '.py', '.s', '.S', '.md', '.txt', '.json', '.sh', '.inc', '.mk'}
    include_names = {'makefile', 'readme', 'license'}
    
    exclude_dirs = {'.git', '__pycache__', 'node_modules', '.vscode', 'build', 'dist'}
    
    for root, dirs, files in os.walk(root_path):
        # Remove excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            file_path = Path(root) / file
            
            # Check if file should be included
            if (file_path.suffix.lower() in include_extensions or 
                file_path.name.lower() in include_names):
                
                print(f"Analyzing: {file_path}")
                
                # Get basic file info
                rel_path = file_path.relative_to(root_path)
                file_size = get_file_size(file_path)
                file_type = get_file_type(file_path)
                
                # Count lines
                line_counts = count_lines(file_path)
                
                # Analyze complexity
                complexity = analyze_complexity(file_path)
                
                results.append({
                    'path': str(rel_path),
                    'filename': file_path.name,
                    'directory': str(rel_path.parent),
                    'type': file_type,
                    'size_bytes': file_size,
                    'size_kb': round(file_size / 1024, 2),
                    **line_counts,
                    **complexity
                })
    
    return results

def generate_summary(results):
    """Generate summary statistics."""
    summary = {
        'total_files': len(results),
        'total_size_bytes': sum(r['size_bytes'] for r in results),
        'total_lines': sum(r['total_lines'] for r in results),
        'total_code_lines': sum(r['code_lines'] for r in results),
        'total_comment_lines': sum(r['comment_lines'] for r in results),
        'total_blank_lines': sum(r['blank_lines'] for r in results),
        'total_functions': sum(r['functions'] for r in results),
        'by_type': {}
    }
    
    # Group by file type
    for result in results:
        file_type = result['type']
        if file_type not in summary['by_type']:
            summary['by_type'][file_type] = {
                'count': 0,
                'total_lines': 0,
                'code_lines': 0,
                'size_bytes': 0
            }
        
        summary['by_type'][file_type]['count'] += 1
        summary['by_type'][file_type]['total_lines'] += result['total_lines']
        summary['by_type'][file_type]['code_lines'] += result['code_lines']
        summary['by_type'][file_type]['size_bytes'] += result['size_bytes']
    
    return summary

def format_bytes(bytes_count):
    """Format bytes in human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"

def generate_markdown_report(results, summary, output_path):
    """Generate a detailed markdown report."""
    
    with open(output_path, 'w') as f:
        f.write("# STAS Source Code Metrics Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Executive Summary
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Files:** {summary['total_files']:,}\n")
        f.write(f"- **Total Size:** {format_bytes(summary['total_size_bytes'])}\n")
        f.write(f"- **Total Lines:** {summary['total_lines']:,}\n")
        f.write(f"- **Lines of Code:** {summary['total_code_lines']:,}\n")
        f.write(f"- **Comment Lines:** {summary['total_comment_lines']:,}\n")
        f.write(f"- **Blank Lines:** {summary['total_blank_lines']:,}\n")
        f.write(f"- **Total Functions:** {summary['total_functions']:,}\n")
        f.write(f"- **Comment Ratio:** {(summary['total_comment_lines'] / max(summary['total_lines'], 1) * 100):.1f}%\n\n")
        
        # Summary by File Type
        f.write("## Summary by File Type\n\n")
        f.write("| File Type | Count | Total Lines | Code Lines | Size |\n")
        f.write("|-----------|-------|-------------|------------|---------|\n")
        
        for file_type, stats in sorted(summary['by_type'].items()):
            f.write(f"| {file_type} | {stats['count']} | {stats['total_lines']:,} | {stats['code_lines']:,} | {format_bytes(stats['size_bytes'])} |\n")
        
        f.write("\n")
        
        # Detailed File Analysis
        f.write("## Detailed File Analysis\n\n")
        f.write("| File | Type | Size | Lines | Code | Comments | Blank | Functions | Complexity |\n")
        f.write("|------|------|------|-------|------|----------|-------|-----------|------------|\n")
        
        # Sort by code lines descending
        sorted_results = sorted(results, key=lambda x: x['code_lines'], reverse=True)
        
        for result in sorted_results:
            f.write(f"| {result['path']} | {result['type']} | {result['size_kb']} KB | {result['total_lines']} | {result['code_lines']} | {result['comment_lines']} | {result['blank_lines']} | {result['functions']} | {result['cyclomatic_complexity']} |\n")
        
        f.write("\n")
        
        # Top Files by Various Metrics
        f.write("## Top Files by Metrics\n\n")
        
        # Largest files by lines of code
        f.write("### Top 10 Files by Lines of Code\n\n")
        f.write("| Rank | File | Lines of Code | Type |\n")
        f.write("|------|------|---------------|------|\n")
        
        top_by_loc = sorted(results, key=lambda x: x['code_lines'], reverse=True)[:10]
        for i, result in enumerate(top_by_loc, 1):
            f.write(f"| {i} | {result['path']} | {result['code_lines']:,} | {result['type']} |\n")
        
        f.write("\n")
        
        # Most complex files
        f.write("### Top 10 Files by Cyclomatic Complexity\n\n")
        f.write("| Rank | File | Complexity | Functions | Type |\n")
        f.write("|------|------|------------|-----------|------|\n")
        
        top_by_complexity = sorted(results, key=lambda x: x['cyclomatic_complexity'], reverse=True)[:10]
        for i, result in enumerate(top_by_complexity, 1):
            f.write(f"| {i} | {result['path']} | {result['cyclomatic_complexity']} | {result['functions']} | {result['type']} |\n")
        
        f.write("\n")
        
        # Largest files by size
        f.write("### Top 10 Files by Size\n\n")
        f.write("| Rank | File | Size | Type |\n")
        f.write("|------|------|---------|------|\n")
        
        top_by_size = sorted(results, key=lambda x: x['size_bytes'], reverse=True)[:10]
        for i, result in enumerate(top_by_size, 1):
            f.write(f"| {i} | {result['path']} | {format_bytes(result['size_bytes'])} | {result['type']} |\n")
        
        f.write("\n")
        
        # Architecture Analysis
        f.write("## Architecture Analysis\n\n")
        
        # Group files by directory for architecture analysis
        arch_stats = {}
        for result in results:
            directory = result['directory']
            if directory not in arch_stats:
                arch_stats[directory] = {
                    'files': 0,
                    'code_lines': 0,
                    'total_lines': 0,
                    'functions': 0,
                    'size_bytes': 0
                }
            
            arch_stats[directory]['files'] += 1
            arch_stats[directory]['code_lines'] += result['code_lines']
            arch_stats[directory]['total_lines'] += result['total_lines']
            arch_stats[directory]['functions'] += result['functions']
            arch_stats[directory]['size_bytes'] += result['size_bytes']
        
        f.write("| Directory | Files | Code Lines | Total Lines | Functions | Size |\n")
        f.write("|-----------|-------|------------|-------------|-----------|------|\n")
        
        for directory, stats in sorted(arch_stats.items(), key=lambda x: x[1]['code_lines'], reverse=True):
            if stats['code_lines'] > 0:  # Only show directories with actual code
                f.write(f"| {directory if directory != '.' else 'Root'} | {stats['files']} | {stats['code_lines']:,} | {stats['total_lines']:,} | {stats['functions']} | {format_bytes(stats['size_bytes'])} |\n")
        
        f.write("\n")
        
        # Code Quality Metrics
        f.write("## Code Quality Metrics\n\n")
        
        total_loc = summary['total_code_lines']
        total_comments = summary['total_comment_lines']
        total_functions = summary['total_functions']
        
        if total_loc > 0:
            comment_density = (total_comments / total_loc) * 100
            avg_function_size = total_loc / max(total_functions, 1)
            
            f.write(f"- **Comment Density:** {comment_density:.1f}% (comments per line of code)\n")
            f.write(f"- **Average Function Size:** {avg_function_size:.1f} lines of code per function\n")
            f.write(f"- **Code Density:** {(total_loc / summary['total_lines']) * 100:.1f}% (code lines vs total lines)\n")
        
        f.write("\n")
        
        # File Type Distribution
        f.write("## File Type Distribution\n\n")
        f.write("```\n")
        for file_type, stats in sorted(summary['by_type'].items(), key=lambda x: x[1]['code_lines'], reverse=True):
            percentage = (stats['code_lines'] / max(summary['total_code_lines'], 1)) * 100
            f.write(f"{file_type:12} | {'█' * int(percentage // 2):20} | {percentage:5.1f}% ({stats['code_lines']:,} lines)\n")
        f.write("```\n\n")

def main():
    """Main function."""
    project_root = Path('/home/tom/project/stas')
    
    print("🔍 Scanning STAS project for source files...")
    results = scan_directory(project_root)
    
    print("📊 Generating summary statistics...")
    summary = generate_summary(results)
    
    print("📝 Creating metrics report...")
    report_path = project_root / 'STAS_METRICS_REPORT.md'
    generate_markdown_report(results, summary, report_path)
    
    # Also save raw data as JSON for further analysis
    json_path = project_root / 'stas_metrics_data.json'
    with open(json_path, 'w') as f:
        json.dump({
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'project_root': str(project_root)
            },
            'summary': summary,
            'files': results
        }, f, indent=2)
    
    print(f"✅ Reports generated:")
    print(f"   📄 Markdown Report: {report_path}")
    print(f"   📊 JSON Data: {json_path}")
    print(f"\n📈 Quick Stats:")
    print(f"   Files analyzed: {summary['total_files']}")
    print(f"   Total lines: {summary['total_lines']:,}")
    print(f"   Lines of code: {summary['total_code_lines']:,}")
    print(f"   Project size: {format_bytes(summary['total_size_bytes'])}")

if __name__ == "__main__":
    main()
