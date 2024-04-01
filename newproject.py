import nmap
import sys

class VulnerabilityScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_targets(self, targets):
        results = []

        for target in targets:
            result = {'target': target, 'scan_results': []}
            print(f"\nScanning {target} for vulnerabilities. This may take a while...")
            scan_result = self.scanner.scan(target, arguments='-p 1-65535 -T4 -A -v')
            result['scan_results'] = scan_result
            results.append(result)

        return results

    def print_results(self, results):
        for result in results:
            target = result['target']
            scan_result = result['scan_results']

            print(f"\nScan report for {target}:")

            for host in scan_result['scan']:
                print(f"\nHost: {host}")
                print(f"State: {scan_result['scan'][host]['status']['state']}")

                for proto in scan_result['scan'][host]['tcp']:
                    state = scan_result['scan'][host]['tcp'][proto]['state']
                    service = scan_result['scan'][host]['tcp'][proto]['name']
                    product = scan_result['scan'][host]['tcp'][proto]['product']
                    version = scan_result['scan'][host]['tcp'][proto]['version']

                    print(f"\nPort: {proto}\tState: {state}\tService: {service}\tProduct: {product}\tVersion: {version}")

                    if 'script' in scan_result['scan'][host]['tcp'][proto]:
                        script_output = scan_result['scan'][host]['tcp'][proto]['script']
                        print(f"Script Output: {script_output}")

    def save_results_to_file(self, results, filename='scan_results.txt'):
        with open(filename, 'w') as file:
            for result in results:
                target = result['target']
                scan_result = result['scan_results']
                file.write(f"Scan report for {target}:\n")

                for host in scan_result['scan']:
                    file.write(f"\nHost: {host}\n")
                    file.write(f"State: {scan_result['scan'][host]['status']['state']}\n")

                    for proto in scan_result['scan'][host]['tcp']:
                        state = scan_result['scan'][host]['tcp'][proto]['state']
                        service = scan_result['scan'][host]['tcp'][proto]['name']
                        product = scan_result['scan'][host]['tcp'][proto]['product']
                        version = scan_result['scan'][host]['tcp'][proto]['version']

                        file.write(f"\nPort: {proto}\tState: {state}\tService: {service}\tProduct: {product}\tVersion: {version}\n")

                        if 'script' in scan_result['scan'][host]['tcp'][proto]:
                            script_output = scan_result['scan'][host]['tcp'][proto]['script']
                            file.write(f"Script Output: {script_output}\n")

def main():
    scanner = VulnerabilityScanner()

    # Ensure proper usage
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <target_ip1> <target_ip2> ...")
        sys.exit(1)

    # Scan targets
    targets = sys.argv[1:]
    scan_results = scanner.scan_targets(targets)

    # Print results
    scanner.print_results(scan_results)

    # Save results to file
    scanner.save_results_to_file(scan_results)

if __name__ == "__main__":
    main()
    
    #DOWNLOAD NMAP FROM NMAP.ORG
    #pip install python-nmap