import subprocess
import os
from datetime import datetime

def run_bandit_scan(repo_path, repo_name):
    """Run Bandit scan on a repository"""
    
    print(f"\n{'='*60}")
    print(f"Analyzing: {repo_name}")
    print(f"Path: {repo_path}")
    print(f"{'='*60}\n")
    
    output_dir = f"analysis_results/{repo_name}"
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    scans = [
        {
            "name": "Full JSON Report",
            "cmd": ["bandit", "-r", repo_path, "-f", "json", 
                   "-o", f"{output_dir}/full_scan_{timestamp}.json"]
        },
        {
            "name": "Full HTML Report",
            "cmd": ["bandit", "-r", repo_path, "-f", "html", 
                   "-o", f"{output_dir}/full_scan_{timestamp}.html"]
        },
        {
            "name": "Full Text Report",
            "cmd": ["bandit", "-r", repo_path, "-f", "txt", 
                   "-o", f"{output_dir}/full_scan_{timestamp}.txt"]
        },
        {
            "name": "High Severity Only",
            "cmd": ["bandit", "-r", repo_path, "-ll", "-f", "txt", 
                   "-o", f"{output_dir}/high_severity_{timestamp}.txt"]
        }
    ]
    
    for scan in scans:
        print(f"▶ Running: {scan['name']}")
        try:
            result = subprocess.run(scan['cmd'], capture_output=True, text=True)
            print(f"  ✓ Completed")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print(f"\n✓ {repo_name} analysis complete!\n")

if __name__ == "__main__":

    # run_bandit_scan("urequest/urllib3", "urllib3")
    # run_bandit_scan("httpie/cli", "httpie")
    run_bandit_scan("python-insecure-app", "python-insecure-app")
    
    print("="*60)
    print("ALL ANALYSES COMPLETE!")
    print("Check the analysis_results folder for reports")
    print("="*60)