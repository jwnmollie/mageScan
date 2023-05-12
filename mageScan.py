import os
import requests
from bs4 import BeautifulSoup
import re

# Patterns to search for in JavaScript files
patterns = ['eval\\(', 'unescape\\(', 'decodeURIComponent\\(', 'atob\\(', '\\.charCodeAt\\(', '\\.fromCharCode\\(', 'var _0x[0-9a-fA-F]+ = \["\\0x']

# Open the file and read the URLs
with open('urls.txt', 'r') as f:
    urls = f.read().splitlines()

# Number of characters to include before and after the match in the snippet
snippet_length = 50

# File to write the output to
output_file = open('output.txt', 'w')

# Loop through the URLs
for url in urls:
    # Fetch the checkout page
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all script tags
    script_tags = soup.find_all('script')

    # Loop through script tags
    for script_tag in script_tags:
        src = script_tag.get('src')
        if src:
            # Fetch the JavaScript file
            js_response = requests.get(src)
            js_content = js_response.text

            # Check for patterns
            for pattern in patterns:
                match = re.search(pattern, js_content)
                if match:
                    start = max(0, match.start() - snippet_length)
                    end = min(len(js_content), match.end() + snippet_length)
                    snippet = js_content[start:end]
                    message = f'Possible obfuscation detected in {src}:\n{snippet}\n'
                    print(message)
                    output_file.write(message)

            # Check for wss:// connections
            match = re.search('wss://', js_content)
            if match:
                start = max(0, match.start() - snippet_length)
                end = min(len(js_content), match.end() + snippet_length)
                snippet = js_content[start:end]
                message = f'Possible WebSocket Secure connection detected in {src}:\n{snippet}\n'
                print(message)
                output_file.write(message)

    # Check header block for abnormalities
    headers = soup.find_all('head')
    for header in headers:
        match = re.search('<script', str(header))
        if match:
            start = max(0, match.start() - snippet_length)
            end = min(len(str(header)), match.end() + snippet_length)
            snippet = str(header)[start:end]
            message = f'Possible script in header detected at {url}:\n{snippet}\n'
            print(message)
            output_file.write(message)

# Close the output file
output_file.close()
