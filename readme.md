# **Running SafePass**

## Installing modules
- Install python from official website. By default it comes with pip.
- Open the command prompt/powershell/terminal and run the following command
- `pip install mysql-connector-python prompt_toolkit pyperclip`
- This will install the required modules.

## Creating Databases
- Install mysql from official website.
- In **MySQL Shell** run the following command to change the language to SQL:
- `\sql`
- Then connect with your login (for example root)
- `\connect root@localhost`
- Next run the follwing to create the database:
- `CREATE DATABASE safepass;`
- To use the databse run:
- `USE safepass;`
- To create the tables run:
- `CREATE TABLE users (user_id INT AUTO_INCREMENT, username VARCHAR(25), password VARCHAR(25), question VARCHAR(100), answer VARCHAR(100), PRIMARY KEY (user_id));`
- `CREATE TABLE passwords (pass_id INT AUTO_INCREMENT, service VARCHAR(100), pass VARCHAR(100), user_id INT, PRIMARY KEY (pass_id), FOREIGN KEY (user_id) REFERENCES users(user_id));`
- Open prefrences.json and replace these:
  - "root" with your MySQL user. Leave it for default user in MySQL
  - "your_password_here" with your MySQL password.
  - "localhost" with your host. Leave it for default user in MySQL

## Running the actual program
- Open Command Prompt/Powershell/Terminal in the folder and run:
- `python SafePass.py`
    ### OR
- Double click the SafePass.py file to run it.
