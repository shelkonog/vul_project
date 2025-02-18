import requests


url = "https://bdu.fstec.ru/files/documents/vulxml.zip"
response = requests.get(url, verify=False)
with open('test_bdu.zip', 'wb') as file:
    file.write(response.content)
