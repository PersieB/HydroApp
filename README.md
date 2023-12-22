Signup and Login Endpoints using Flask
Using the POST method with a JSON payload for security reasons. 
Database: PostgreSQL

Signup endpoint: http://127.0.0.1:5000/signup
Login endpoint: http://127.0.0.1:5000/login

Example testing with curl in terminal below:
´curl -X POST -H "Content-Type: application/json" -d '{"name":"Percy","email":"pbrown@gmail.com","phone":"+23333","password":"hydro"}' http://127.0.0.1:5000/signup´
