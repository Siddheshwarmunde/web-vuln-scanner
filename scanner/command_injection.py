import requests
import time

def scan_command_injection(url):
    payloads = ["; ls", "| ls", "| cat /etc/passwd"]
    vulnerable = False
    result = {"vulnerable": "No", "payload": "", "time_taken": ""}
    
    for payload in payloads:
        test_url = url + payload
        try:
            # Start the timer to measure time taken
            start_time = time.time()
            response = requests.get(test_url)
            end_time = time.time()

            # Check for specific command injection indicators (simplified)
            if "root" in response.text or "bin" in response.text:
                vulnerable = True
                result["vulnerable"] = "Yes"
                result["payload"] = payload
                result["time_taken"] = round(end_time - start_time, 3)
                break
        except requests.RequestException as e:
            result["vulnerable"] = "Error in Request"
    
    return result
