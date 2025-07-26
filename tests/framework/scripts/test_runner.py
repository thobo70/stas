#!/usr/bin/env python3

"""
STAS Comprehensive Test Runner
Orchestrates all testing categories for complete quality assurance
"""

import subprocess
import sys
import json
import time
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

class STASTestRunner:
    def __init__(self):
        self.results = {
            'unit_tests': {},
            'integration_tests': {},
            'execution_tests': {},
            'build_tests': {},
            'coverage': {}
        }
        self.start_time = time.time()
        self.project_root = Path.cwd()
    
    def log_info(self, message: str):
        print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")
    
    def log_success(self, message: str):
        print(f"{Colors.GREEN}[PASS]{Colors.NC} {message}")
    
    def log_error(self, message: str):
        print(f"{Colors.RED}[FAIL]{Colors.NC} {message}")
    
    def log_warning(self, message: str):
        print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")
    
    def run_command(self, cmd: str, cwd: str = None) -> Tuple[bool, str, str]:
        """Run a command and return success, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                cwd=cwd or self.project_root,
                timeout=300  # 5 minute timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out after 5 minutes"
        except Exception as e:
            return False, "", str(e)
    
    def check_prerequisites(self) -> bool:
        """Check if all required tools and dependencies are available"""
        self.log_info("Checking prerequisites...")
        
        # Check for required files
        required_files = ['Makefile', 'src/', 'include/', 'tests/']
        for file in required_files:
            if not (self.project_root / file).exists():
                self.log_error(f"Required file/directory missing: {file}")
                return False
        
        # Check for Unity framework
        unity_files = ['tests/unity.h', 'tests/unity.c']
        for file in unity_files:
            if not (self.project_root / file).exists():
                self.log_warning(f"Unity file missing: {file}")
        
        # Check for Unicorn Engine
        success, _, _ = self.run_command("pkg-config --exists libunicorn")
        if not success:
            # Try alternative check
            success, _, _ = self.run_command("ldconfig -p | grep unicorn")
            if not success:
                self.log_warning("Unicorn Engine not found - execution tests may fail")
        
        # Check for GCC
        success, _, _ = self.run_command("gcc --version")
        if not success:
            self.log_error("GCC compiler not found")
            return False
        
        # Check for coverage tools
        success, _, _ = self.run_command("gcov --version")
        if not success:
            self.log_warning("gcov not found - coverage analysis disabled")
        
        self.log_success("Prerequisites check completed")
        return True
    
    def run_unit_tests(self) -> bool:
        """Run Unity-based unit tests with coverage"""
        print(f"\n{Colors.PURPLE}=== Running Unit Tests ==={Colors.NC}")
        
        # First ensure testbin directory exists
        success, _, stderr = self.run_command("make $(TESTBIN_DIR)")
        if not success:
            self.log_error(f"Failed to create testbin directory: {stderr}")
        
        test_categories = ['core', 'arch', 'formats', 'utils']
        overall_success = True
        
        for category in test_categories:
            self.log_info(f"Testing {category} module...")
            
            # Check if make target exists
            success, stdout, stderr = self.run_command(f"make -n test-unit-{category}")
            if not success:
                self.log_warning(f"No unit tests found for {category} - skipping")
                self.results['unit_tests'][category] = {
                    'passed': True,
                    'output': f"No tests defined for {category}",
                    'errors': '',
                    'skipped': True
                }
                continue
            
            # Run the tests
            success, stdout, stderr = self.run_command(f"make test-unit-{category}")
            
            self.results['unit_tests'][category] = {
                'passed': success,
                'output': stdout,
                'errors': stderr,
                'skipped': False
            }
            
            if success:
                self.log_success(f"{category} unit tests passed")
            else:
                self.log_error(f"{category} unit tests failed")
                print(f"Error details:\n{stderr}")
                overall_success = False
        
        return overall_success
    
    def run_build_tests(self) -> bool:
        """Test all build variants"""
        print(f"\n{Colors.PURPLE}=== Running Build Variant Tests ==={Colors.NC}")
        
        script_path = "tests/integration/build_variants/test_all_builds.sh"
        if not (self.project_root / script_path).exists():
            self.log_error(f"Build test script not found: {script_path}")
            return False
        
        success, stdout, stderr = self.run_command(script_path)
        
        self.results['build_tests'] = {
            'passed': success,
            'output': stdout,
            'errors': stderr
        }
        
        if success:
            self.log_success("All build variants working")
        else:
            self.log_error("Some build variants failed")
            print(f"Error details:\n{stderr}")
        
        return success
    
    def run_execution_tests(self) -> bool:
        """Run Unicorn-based execution tests"""
        print(f"\n{Colors.PURPLE}=== Running Execution Tests ==={Colors.NC}")
        
        architectures = ['x86_16', 'x86_32', 'x86_64', 'arm64', 'riscv']
        overall_success = True
        
        for arch in architectures:
            self.log_info(f"Testing {arch} execution...")
            
            # Check if execution tests exist for this architecture
            success, stdout, stderr = self.run_command(f"make -n test-execution-{arch}")
            if not success:
                self.log_warning(f"No execution tests found for {arch} - skipping")
                self.results['execution_tests'][arch] = {
                    'passed': True,
                    'output': f"No execution tests defined for {arch}",
                    'errors': '',
                    'skipped': True
                }
                continue
            
            # Run the tests
            success, stdout, stderr = self.run_command(f"make test-execution-{arch}")
            
            self.results['execution_tests'][arch] = {
                'passed': success,
                'output': stdout,
                'errors': stderr,
                'skipped': False
            }
            
            if success:
                self.log_success(f"{arch} execution tests passed")
            else:
                self.log_error(f"{arch} execution tests failed")
                print(f"Error details:\n{stderr}")
                overall_success = False
        
        return overall_success
    
    def run_integration_tests(self) -> bool:
        """Run integration tests"""
        print(f"\n{Colors.PURPLE}=== Running Integration Tests ==={Colors.NC}")
        
        # Check if integration test target exists
        success, stdout, stderr = self.run_command("make -n test-integration")
        if not success:
            self.log_warning("No integration tests defined - running legacy test-all")
            success, stdout, stderr = self.run_command("make test-all")
        else:
            success, stdout, stderr = self.run_command("make test-integration")
        
        self.results['integration_tests'] = {
            'passed': success,
            'output': stdout,
            'errors': stderr
        }
        
        if success:
            self.log_success("Integration tests passed")
        else:
            self.log_error("Integration tests failed")
            print(f"Error details:\n{stderr}")
        
        return success
    
    def run_instruction_completeness_tests(self) -> bool:
        """Run instruction completeness tests"""
        print(f"\n{Colors.PURPLE}=== Running Instruction Completeness Tests ==={Colors.NC}")
        
        success, stdout, stderr = self.run_command("make test-instruction-completeness")
        
        self.results['instruction_completeness'] = {
            'passed': success,
            'output': stdout,
            'errors': stderr
        }
        
        if success:
            self.log_success("Instruction completeness tests passed")
        else:
            self.log_error("Instruction completeness tests failed")
            print(f"Error details:\n{stderr}")
        
        return success
    
    def extract_instruction_completeness_percentage(self, output: str) -> str:
        """Extract overall instruction completeness percentage from output"""
        import re
        
        # Find all OVERALL lines with pattern: | OVERALL  |  XX/YY  [########] [########] |
        overall_matches = re.findall(r'OVERALL\s+\|\s+(\d+)/(\d+)', output)
        
        if overall_matches:
            total_implemented = 0
            total_instructions = 0
            
            # Sum up all architectures
            for implemented_str, total_str in overall_matches:
                implemented = int(implemented_str)
                total = int(total_str)
                total_implemented += implemented
                total_instructions += total
            
            if total_instructions > 0:
                percentage = (total_implemented / total_instructions) * 100
                return f"{percentage:.1f}%"
        
        # Fallback: look for any percentage pattern if OVERALL format not found
        percentage_match = re.search(r'(\d+\.\d+)%.*?functional', output)
        if percentage_match:
            return f"{percentage_match.group(1)}%"
        
        return "N/A"
    
    def extract_coverage_percentage(self, output: str) -> str:
        """Extract overall line coverage percentage from output"""
        import re
        
        # Look for lcov output pattern: "lines......: XX.X% (xxx of xxx lines)"
        coverage_match = re.search(r'lines\.+:\s*(\d+\.\d+)%', output)
        if coverage_match:
            return f"{coverage_match.group(1)}%"
        
        return "N/A"
    
    def generate_coverage(self) -> bool:
        """Generate code coverage report"""
        print(f"\n{Colors.PURPLE}=== Generating Code Coverage ==={Colors.NC}")
        
        # Check if coverage script exists
        coverage_script = "tests/coverage/generate_coverage.sh"
        if not (self.project_root / coverage_script).exists():
            self.log_warning("Coverage script not found - skipping coverage analysis")
            self.results['coverage'] = {
                'generated': False,
                'output': 'Coverage script not found',
                'errors': 'tests/coverage/generate_coverage.sh missing'
            }
            return True  # Don't fail the entire test run
        
        success, stdout, stderr = self.run_command(coverage_script)
        
        self.results['coverage'] = {
            'generated': success,
            'output': stdout,
            'errors': stderr
        }
        
        if success:
            self.log_success("Coverage report generated")
        else:
            self.log_warning("Coverage generation failed")
            print(f"Error details:\n{stderr}")
        
        return True  # Don't fail the test run for coverage issues
    
    def run_performance_tests(self) -> bool:
        """Run performance benchmarks if available"""
        print(f"\n{Colors.PURPLE}=== Running Performance Tests ==={Colors.NC}")
        
        # Check if performance tests exist
        success, stdout, stderr = self.run_command("make -n test-performance")
        if not success:
            self.log_info("No performance tests defined - skipping")
            return True
        
        success, stdout, stderr = self.run_command("make test-performance")
        
        self.results['performance_tests'] = {
            'passed': success,
            'output': stdout,
            'errors': stderr
        }
        
        if success:
            self.log_success("Performance tests completed")
        else:
            self.log_warning("Performance tests failed")
        
        return True  # Don't fail for performance test issues
    
    def calculate_summary(self) -> Dict[str, Any]:
        summary = {
            'total_categories': 0,
            'passed_categories': 0,
            'unit_tests': 'unknown',
            'build_tests': 'unknown',
            'execution_tests': 'unknown',
            'integration_tests': 'unknown',
            'instruction_completeness': 'unknown',
            'coverage': 'unknown'
        }
        
        # Unit tests
        if self.results['unit_tests']:
            unit_passed = all(
                test.get('passed', False) or test.get('skipped', False) 
                for test in self.results['unit_tests'].values()
            )
            summary['unit_tests'] = 'passed' if unit_passed else 'failed'
            summary['total_categories'] += 1
            if unit_passed:
                summary['passed_categories'] += 1
        
        # Build tests
        if self.results['build_tests']:
            summary['build_tests'] = 'passed' if self.results['build_tests']['passed'] else 'failed'
            summary['total_categories'] += 1
            if self.results['build_tests']['passed']:
                summary['passed_categories'] += 1
        
        # Execution tests
        if self.results['execution_tests']:
            exec_passed = all(
                test.get('passed', False) or test.get('skipped', False)
                for test in self.results['execution_tests'].values()
            )
            summary['execution_tests'] = 'passed' if exec_passed else 'failed'
            summary['total_categories'] += 1
            if exec_passed:
                summary['passed_categories'] += 1
        
        # Integration tests
        if self.results['integration_tests']:
            summary['integration_tests'] = 'passed' if self.results['integration_tests']['passed'] else 'failed'
            summary['total_categories'] += 1
            if self.results['integration_tests']['passed']:
                summary['passed_categories'] += 1
        
        # Instruction completeness
        if self.results['instruction_completeness']:
            summary['instruction_completeness'] = 'passed' if self.results['instruction_completeness']['passed'] else 'failed'
            summary['total_categories'] += 1
            if self.results['instruction_completeness']['passed']:
                summary['passed_categories'] += 1
        
        # Coverage
        if self.results['coverage']:
            summary['coverage'] = 'passed' if self.results['coverage']['generated'] else 'failed'
        
        return summary
    
    def generate_report(self):
        """Generate comprehensive test report"""
        end_time = time.time()
        duration = end_time - self.start_time
        
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': f"{duration:.2f} seconds",
            'summary': self.calculate_summary(),
            'details': self.results
        }
        
        # Save JSON report
        try:
            # Ensure logs directory exists
            os.makedirs('logs', exist_ok=True)
            with open('logs/test_report.json', 'w') as f:
                json.dump(report, f, indent=2)
            self.log_success("Test report saved to logs/test_report.json")
        except Exception as e:
            self.log_warning(f"Failed to save test report: {e}")
        
        # Print summary
        self.print_summary(report['summary'], duration)
    
    def print_summary(self, summary: Dict[str, Any], duration: float):
        print("\n" + "="*70)
        print(f"{Colors.CYAN}STAS COMPREHENSIVE TEST RESULTS{Colors.NC}")
        print("="*70)
        
        print(f"Unit Tests:       {self.format_status(summary['unit_tests'])}")
        print(f"Build Tests:      {self.format_status(summary['build_tests'])}")
        print(f"Execution Tests:  {self.format_status(summary['execution_tests'])}")
        print(f"Integration Tests:{self.format_status(summary['integration_tests'])}")
        print(f"Instruction Completeness:{self.format_status_with_percentage('instruction_completeness', summary)}")
        print(f"Code Coverage:    {self.format_status_with_percentage('coverage', summary)}")
        
        print(f"\nOverall: {summary['passed_categories']}/{summary['total_categories']} categories passed")
        
        if summary['passed_categories'] == summary['total_categories']:
            print(f"\n{Colors.GREEN}🎉 ALL TESTS PASSED! STAS is ready for release.{Colors.NC}")
        else:
            print(f"\n{Colors.RED}❌ Some tests failed. Review the detailed report.{Colors.NC}")
        
        print(f"Test duration: {duration:.2f} seconds")
        print("="*70)
    
    def format_status(self, status: str) -> str:
        if status == 'passed':
            return f"{Colors.GREEN}✅ PASSED{Colors.NC}"
        elif status == 'failed':
            return f"{Colors.RED}❌ FAILED{Colors.NC}"
        else:
            return f"{Colors.YELLOW}⚠️  UNKNOWN{Colors.NC}"
    
    def format_status_with_percentage(self, test_type: str, summary: Dict[str, Any]) -> str:
        """Format status with percentage for instruction completeness and coverage"""
        status = summary.get(test_type, 'unknown')
        
        if status == 'passed':
            if test_type == 'instruction_completeness':
                # Extract percentage from instruction completeness results
                if 'instruction_completeness' in self.results and self.results['instruction_completeness']:
                    output = self.results['instruction_completeness'].get('output', '')
                    percentage = self.extract_instruction_completeness_percentage(output)
                    return f"{Colors.GREEN}✅ PASSED ({percentage}){Colors.NC}"
            elif test_type == 'coverage':
                # Extract percentage from coverage results
                if 'coverage' in self.results and self.results['coverage']:
                    output = self.results['coverage'].get('output', '')
                    percentage = self.extract_coverage_percentage(output)
                    return f"{Colors.GREEN}✅ PASSED ({percentage}){Colors.NC}"
            
            # Fallback to regular PASSED if percentage extraction fails
            return f"{Colors.GREEN}✅ PASSED{Colors.NC}"
        elif status == 'failed':
            return f"{Colors.RED}❌ FAILED{Colors.NC}"
        else:
            return f"{Colors.YELLOW}⚠️  UNKNOWN{Colors.NC}"

def main():
    print(f"{Colors.CYAN}🚀 Starting STAS Comprehensive Test Suite...{Colors.NC}")
    
    runner = STASTestRunner()
    
    # Check prerequisites
    if not runner.check_prerequisites():
        print(f"{Colors.RED}❌ Prerequisites check failed. Cannot continue.{Colors.NC}")
        return 1
    
    overall_success = True
    
    try:
        # Run all test categories
        test_categories = [
            ("Unit Tests", runner.run_unit_tests),
            ("Build Tests", runner.run_build_tests),
            ("Execution Tests", runner.run_execution_tests),
            ("Integration Tests", runner.run_integration_tests),
            ("Instruction Completeness", runner.run_instruction_completeness_tests),
        ]
        
        for category_name, test_func in test_categories:
            try:
                if not test_func():
                    overall_success = False
            except Exception as e:
                runner.log_error(f"{category_name} failed with exception: {e}")
                overall_success = False
        
        # Generate coverage (non-critical)
        try:
            runner.generate_coverage()
        except Exception as e:
            runner.log_warning(f"Coverage generation failed: {e}")
        
        # Run performance tests (non-critical)
        try:
            runner.run_performance_tests()
        except Exception as e:
            runner.log_warning(f"Performance tests failed: {e}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Test run interrupted by user{Colors.NC}")
        return 1
    except Exception as e:
        print(f"\n{Colors.RED}❌ Test run failed with error: {e}{Colors.NC}")
        return 1
    finally:
        runner.generate_report()
    
    # Return appropriate exit code
    return 0 if overall_success else 1

if __name__ == "__main__":
    sys.exit(main())
