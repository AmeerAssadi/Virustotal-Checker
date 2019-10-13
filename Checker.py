import requests


def cred():
    apiKey = 'ADD_YOUR_KEY'
    return apiKey


def checkURL(url):
    print("Scanning", url)
    scanURL = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': cred(), 'url': url}
    response = requests.post(scanURL, data=params)
    print("Scan URL: ", response.json()["permalink"])


def getREPORT(url):
    reportURL = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': cred(), 'resource': url}
    response = requests.get(reportURL, params=params)
    if response.json()["positives"] > 0:
        print(response.json()["positives"], "engines detected this URL")
    else:
        print("No engines detected this URL!")


def fileSCAN(path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': cred()}
    files = {'file': (path, open(path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    resource = response.json()['resource']
    # print("Scan URL: ", response.json()['permalink'])
    return getfileREPORT(resource)


def getfileREPORT(resource):
    import requests
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': cred(), 'resource': resource}
    response = requests.get(url, params=params)
    print("Scan URL: ", response.json()['permalink'])
    if response.json()["positives"] > 0:
        print(response.json()['positives'],"engines deteced this file :)")
    else:
        print("No engines detected this URL!")


def main():
    print("# Analyze suspicious URLs and Files to detect types of malware, automatically.")
    print("What you would like to scan?\n[1] URL\n[2] FILE")
    choice = int(input("choose or 1 or 2: "))
    if choice == 1:
        inpURL = input('Enter a URL to scan: ')
        checkURL(inpURL)
        getREPORT(inpURL)
    if choice == 2:
        path = input("Enter the path of the file: ")
        fileSCAN(path)
    else:
        print("Bad Choice")

if __name__ == '__main__':
    main()

