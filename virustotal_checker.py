import requests
import sys
import base64
import json

# Replace with your actual VirusTotal API key
API_KEY = 'fd03345befd8c07118ee867e15ba7c147beec2f4f8104f4034855c17e22a7581'
BASE_URL = 'https://www.virustotal.com/api/v3'

def get_virus_total_report(url):
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(f'{BASE_URL}/urls/{url}', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': f"Error fetching data: {response.status_code}"}

def analyze_url(url):
    # Encode the URL to Base64
    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    
    report = get_virus_total_report(url_encoded)
    if report and 'error' not in report:
        attributes = report.get('data', {}).get('attributes', {})
        
        categories = attributes.get('categories', {})
        
        return json.dumps(categories, indent=4)  # Return only the categories in JSON
    else:
        return json.dumps({'error': 'Failed to retrieve the report.'}, indent=4)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({'error': 'Usage: python virustotal_checker.py <url>'}, indent=4))
        sys.exit(1)
    
    url = sys.argv[1]

    print(analyze_url(url))
  

  