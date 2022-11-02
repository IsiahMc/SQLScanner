from bs4 import BeautifulSoup
import requests
import sys
from urllib.parse import urljoin
import PySimpleGUI as sg

s = requests.Session()
s.headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"


# When given URL make request to page and extract HTML form tags
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")


# get form details
def form_details(form):
    form_details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    # iterate over form and put values into inputs list
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")

        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })

    form_details['action'] = action
    form_details['method'] = method
    form_details['inputs'] = inputs
    return form_details

# check for error in response
def vulnerable(response):
    errors = {"quoted string was not properlly terminated",
              "quotation mark not closed after the character",
              "error found in SQL syntax"}

    for error in errors:
        if error in response.content.decode().lower():
            return True
        return False
# scan form
def sql_scan(url):
    forms = get_forms(url)
   # getUrl = input()
    print(f"[+] detected {len(forms)} forms on {url}")

    for form in forms:
        details = form_details(form)

    for i in "\"'":
        data = {}
        for input_tag in details["inputs"]:
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[input_tag["name"]] = input_tag["value"]
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test{i}"
            print(url)
            form_details(form)

            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)
            if vulnerable(res):
                print("SQL injection vulnerability found in", url)
            else:
                print("No SQL injection vulnerability found")
                break


if __name__ == '__main__':
    print("Enter url: ")
    urlToCheck = input()
    sql_scan(urlToCheck)


