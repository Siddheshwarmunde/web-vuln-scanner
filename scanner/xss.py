import time
import requests

def scan_xss(test_url):
    start_time = time.time()

    # Example payload for XSS testing
    payload = "<script>alert('XSS')</script>"
    test_url_with_payload = f"{test_url}?search={payload}"

    try:
        response = requests.get(test_url_with_payload)
        end_time = time.time()

        if payload in response.text:
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
