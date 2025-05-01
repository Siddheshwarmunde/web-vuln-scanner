import time
import requests

def scan_sqli(test_url):
    start_time = time.time()

    # Example payload for SQL Injection testing
    payload = "' OR 1=1 --"
    test_url_with_payload = f"{test_url}?id={payload}"

    try:
        response = requests.get(test_url_with_payload)
        end_time = time.time()

        if "error" in response.text.lower() or "sql" in response.text.lower():
            return {
                'vulnerable': 'Yes',
                'payload': payload,
                'time_taken': round(end_time - start_time, 4)
            }
        else:
            return {
                'vulnerable': 'No',
                'payload': payload,
                'time_taken': round(end_time - start_time, 4)
            }
    except requests.exceptions.RequestException:
        return {'vulnerable': 'Error', 'payload': payload, 'time_taken': 'N/A'}
