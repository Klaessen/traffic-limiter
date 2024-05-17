import ipaddress
import subprocess
import requests

# Define the log file path
LOG_FILE = "/var/log/nginx/https.access.log.1"

# Define the threshold
THRESHOLD = 10000

# Define the whitelist file path
WHITELIST_FILE = "/etc/openresty/whitelist.conf"


def update_whitelist():
    # URLs to fetch the Googlebot ang Bingbot IP ranges
    ip_ranges_url_google = "https://developers.google.com/search/apis/ipranges/googlebot.json"
    ip_ranges_url_bing = "https://www.bing.com/toolbox/bingbot.json"

    try:
        # Fetch the IP ranges from the Google Developers page
        response_google = requests.get(ip_ranges_url_google)
        response_google.raise_for_status()  # Raise an error if the request was unsuccessful
        
        # Fetch the IP ranges from the Bing Developers page
        response_bing = requests.get(ip_ranges_url_bing)
        response_bing.raise_for_status()  # Raise an error if the request was unsuccessful

        # Parse the JSON response
        data_google = response_google.json()
        data_bing = response_bing.json()

        # Extract the IPv4 and IPv6 ranges
        ipv4_ranges_google = [item["ipv4Prefix"] for item in data_google["prefixes"] if "ipv4Prefix" in item]
        ipv6_ranges_google = [item["ipv6Prefix"] for item in data_google["prefixes"] if "ipv6Prefix" in item]
        ipv4_ranges_bing = [item["ipv4Prefix"] for item in data_bing["prefixes"] if "ipv4Prefix" in item]
        ipv6_ranges_bing = [item["ipv6Prefix"] for item in data_bing["prefixes"] if "ipv6Prefix" in item]

        # Prepare the whitelist content
        whitelist_content = "\n".join([f"{ip_range} 1;" for ip_range in ipv4_ranges_google + ipv6_ranges_google + ipv4_ranges_bing + ipv6_ranges_bing])

        # Save the whitelist to a configuration file
        with open(WHITELIST_FILE, "w") as file:
            file.write(whitelist_content)

        print("Whitelist updated successfully.")

        # Test the OpenResty configuration
        test_command = subprocess.run(["sudo", "openresty", "-t"], check=True)

        if test_command.returncode == 0:
            # Reload OpenResty to apply the new configuration
            subprocess.run(["sudo", "openresty", "-s", "reload"], check=True)

            print("OpenResty reloaded successfully.")
        else:
            print("OpenResty configuration test failed.")

    except Exception as e:
        print(f"Error: {e}")


def rate_limit_ips():
    whitelist = []
    with open(WHITELIST_FILE, 'r') as file:
        for line in file:
            if line.strip():
                cidr = line.split()[0]
                whitelist.append(ipaddress.ip_network(cidr))

    def is_ip_whitelisted(ip):
        ip_addr = ipaddress.ip_address(ip)
        for network in whitelist:
            if ip_addr in network:
                return True
        return False

    # Extract IPs with more than the threshold requests
    with open(LOG_FILE, 'r') as file:
        ip_counts = {}
        for line in file:
            ip = line.split()[0]
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

    offending_ips = [ip for ip, count in ip_counts.items() if count > THRESHOLD]

    # Loop through the offending IPs and add a UFW rule for each if not whitelisted
    for ip in offending_ips:
        if not is_ip_whitelisted(ip):
            subprocess.run(['ufw', 'insert', '1', 'limit', 'from', ip, 'to', 'any'], check=True)
            print(f"Rate limited IP: {ip}")
        else:
            print(f"Whitelisted IP: {ip}")
            

if __name__ == "__main__":
    update_whitelist()
    rate_limit_ips()
