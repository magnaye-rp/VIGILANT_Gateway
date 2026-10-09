import requests
import concurrent.futures

# Configuration
NUM_REQUESTS = 1000
TARGET_URLS = [
    "http://example.com",
    "https://example.com",
    "http://neverssl.com"
]

def make_request(url):
    try:
        # We disable SSL verification here just in case the gateway intercepts HTTPS 
        # and presents a self-signed cert, to ensure the request actually goes through.
        response = requests.get(url, timeout=5, verify=False)
        return True, response.status_code
    except Exception as e:
        return False, str(e)

def run_interception_test():
    print(f"Starting Interception Test: Sending {NUM_REQUESTS} requests...")
    success_count = 0
    fail_count = 0
    
    urls_to_request = [TARGET_URLS[i % len(TARGET_URLS)] for i in range(NUM_REQUESTS)]
    
    # Send requests concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(make_request, urls_to_request))
        
    for success, _ in results:
        if success:
            success_count += 1
        else:
            fail_count += 1
            
    print("-" * 40)
    print(f"Total Requests Attempted: {NUM_REQUESTS}")
    print(f"Successful Client Requests: {success_count}")
    print(f"Failed Client Requests: {fail_count}")
    print("-" * 40)
    print("Action Required on VIGILANT Gateway:")
    print("1. Count the number of intercepted HTTP/HTTPS requests logged by the gateway for this client IP.")
    print("2. Calculate: (Gateway Logged Requests / Successful Client Requests) * 100")
    print("3. Target: >= 95%")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    run_interception_test()
