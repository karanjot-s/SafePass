# Creating Database
`CREATE DATABASE safepass;`

## Using the database
`USE safepass;`

# Creating the tables

## "users" table
`CREATE TABLE users (user_id INT AUTO_INCREMENT, username VARCHAR(25), password VARCHAR(25), question VARCHAR(100), answer VARCHAR(100), PRIMARY KEY (user_id));`

## "passwords" table
`CREATE TABLE passwords (pass_id INT AUTO_INCREMENT, service VARCHAR(100), pass VARCHAR(100), user_id INT, PRIMARY KEY (pass_id), FOREIGN KEY (user_id) REFERENCES users(user_id));`
