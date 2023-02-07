
# PortSwigger Academy Lab automation scripts

>Came across this great YouTube channel by [@tjc_](https://www.youtube.com/@tjc_/videos), where he step through the process of writng python scripts to automate the exploitation of the PortSwigger labs.  
  
>I followed his videos and reproduced the scripts but credit goes to **@tjc_**  

>The utils and other pythons scripts imported into each vulnerability catagory lab is reference with symbolic link, under each sub folder. In below example in the XSS folder there is symbolic link to ../utils folder.

```bash
cd xss/
ln -s ../utils utils
```  

>This create uniform import standard in all scripts.  
