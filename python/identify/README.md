# Python Identification Script

>Updated identification of key words in headers and body script. Added the ```--screenshot``` optional to capture screenshot image of the page loaded.    
  
```bash
python web-identifiers-v3.py https://TARGET.net/ ./SEARCH_headers_TERMS.txt ./SEARCH_body_TERMS.txt --screenshot

feh screenshot-2023-03-11-14-43-20.png

```  

![python web identifiers usage](web-identifiers.png)  

>Requirements to capture the screenshot is chromium and chromiumdriver.  

```sh
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
google-chrome

export PATH="/home/kali/Downloads/python-scripts/chromedriver:$PATH"
```  

>Version that worked for me 111.x.  