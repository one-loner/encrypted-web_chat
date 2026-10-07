# Encrypted-webchat   
Чат, где шифрование производится на стороне клиента.   
Требования: вебсервер с php   
Так же необходимо правильно установить владельца www-data:www-data на все файлы проекта и поместить их в корневую папку веб-сервера.
Для обеспечения безопасности необходимо запретить доступ к папке private со стороны клиента.
Учётные записи пользователей хранятся в файле private/users.txt в формате user:encrypted_password
Создание пароля:   
При помощи php: php -r "echo password_hash('PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"    
При помощи htpasswd: htpasswd -nB username   


