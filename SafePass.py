# Imports
from mysql.connector import connect as sql_connect
from prompt_toolkit import prompt  # pip install prompt_toolkit
from time import sleep
import pyperclip  # pip install pyperclip
import json
import os


# Functions


def make_pref_file():
    """
    Make a preferences.json file
    """
    pref_dict = {"default_user": None}

    with open(os.path.join(os.path.dirname(__file__), "preferences.json"), "w") as pref:
        pref.write(json.dumps(pref_dict, indent=4))

    return pref_dict


def take_pass(text_to_prompt):
    """
    Take password input from user
    """
    return prompt(text_to_prompt, is_password=True)


def fetch_data(cursor, *tables):
    """
    Fetch all the data from database
    """
    final = []

    for table in tables:

        cursor.execute(f"SELECT * FROM {table};")
        data = cursor.fetchall()
        final.append(data)

    try:
        return final if len(final) > 1 else final[0]
    except:
        return []


def db_change(table, column, value, condition):
    """
    Updates database
    """
    global database
    global sql_cursor
    global users
    global passwords

    query = f'UPDATE {table} SET {column}="{value}" WHERE {condition};'
    sql_cursor.execute(query)
    database.commit()

    users, passwords = fetch_data(sql_cursor, "users", "passwords")


def get_preferences():
    """
    Loads the preferences
    """
    try:
        with open(os.path.join(os.path.dirname(__file__), "preferences.json")) as pref:
            pref_dict = json.loads(pref.read())
        return pref_dict

    except:
        return make_pref_file()


def update_pref(key, value):
    """
    Updates the preferences
    """
    global pref

    pref[key] = value

    with open(
        os.path.join(os.path.dirname(__file__), "preferences.json"), "w"
    ) as prefer:
        prefer.write(json.dumps(pref, indent=4))


def login(users_list, default=None):
    """
    Welcomes the user with login menu
    """
    global pref
    user_present = False

    while not user_present:

        if pref["default_user"]:
            username = pref["default_user"]

        else:
            print("\nEnter your username. Enter new if you are a new user.")
            username = input("Username : ")

        if username == "new":
            username = register_user(users_list)
            continue

        for user_num in range(len(users_list)):
            if username == users_list[user_num][1]:

                user_present = True  # breaks the while loop
                user_id = users_list[user_num][0]
                user = users_list[user_num][1]
                user_pass = users_list[user_num][2]
                user_ques = users_list[user_num][3]
                user_ans = users_list[user_num][4]

                break

        else:
            print("Incorrect Username\nTry Again")

    pass_corr = False
    forgot_pass = False

    while not pass_corr:

        if forgot_pass:
            print(f"\nEnter the password for {username}")
        else:
            print(f"\nEnter the password for {username}. Forgot password? Type forgot")
            print(f"If you are not {username} enter 0")

        password = take_pass("Password : ")

        if password == "forgot" and not forgot_pass:
            user_pass = reset_pass(
                username, user_pass, user_ques, user_ans, forgot_pass=True
            )
            forgot_pass = True

            continue

        if password == "0":

            user_present = False
            while not user_present:
                print("Enter your username. Enter new if you are a new user.")
                username = input("Username : ")
                if username == "new":
                    username = register_user(users_list)
                    continue
                for user_num in range(len(users_list)):
                    if username == users_list[user_num][1]:
                        user_present = True  # breaks the while loop
                        user_id = users_list[user_num][0]
                        user = users_list[user_num][1]
                        user_pass = users_list[user_num][2]
                        user_ques = users_list[user_num][3]
                        user_ans = users_list[user_num][4]
                        break
                else:
                    print("Incorrect Username\nTry Again\n")

        if password == user_pass:
            pass_corr = True
        else:
            print("Invalid password.\nTry Again\n")

    while True:
        print(f"\nDo you want to set {user} as your default user?")
        def_user = input("Your input (y/n) : ")

        if def_user in "yY":
            update_pref("default_user", user)
            break

        elif def_user in "nN":
            break
        else:
            print("Invalid input")
            print("Try Again\n")

    print(f"\nWelcome {user}\n")

    return {
        "id": user_id,
        "name": user,
        "password": user_pass,
        "ques": user_ques,
        "ans": user_ans,
    }


def reset_pass(username, password, question, answer, forgot_pass=False):
    """
    Resets the password
    """
    reset = False

    while not reset:

        if forgot_pass:

            print("To reset the passord, answer this question.")
            print("Type cancel to cancel resetting password")

            if question[len(question) - 1] == "?":
                print(question)
            else:
                print(question + "?")

            ans_inp = take_pass("Your answer : ")

            if ans_inp.lower == "cancel":
                return
            if ans_inp == answer:
                print("Correct Answer!\n")
                reset = True
            else:
                print("\nWrong Answer.")
                print(f"Are you the real owner of {username}?")
                print("Anyways try again\n")

        else:
            print("Confirm your old password")
            print("Type cancel to cancel the resetting of password.")

            old_pass = take_pass("Old Password : ")
            if old_pass.lower == "cancel":

                return

            if old_pass == "forgot":
                forgot_pass == True
            elif old_pass == password:

                break

            else:
                print("Invalid Password.")
                print("If you forgot your password enter forgot")

    print("Now enter the new password")

    while True:
        new_pass = take_pass("New Password : ")
        if valid_pass(new_pass) and new_pass != password:

            print("Confirm the new password")
            if new_pass == take_pass("New Password : "):

                db_change("users", "password", new_pass, f'username="{username}"')
                print("Password successfuly updated")

                return new_pass

            else:
                print("Your passwords don't match.")
                print("Enter your password again")


def valid_user(username, user_list):
    """
    Checks if username is valid
    """
    if len(username) >= 6 and len(username) <= 20 and username != "username":

        for user in user_list:

            if user[1] == username:

                print("This username already exists")
                return False

        return True  # This will only occur if loop is not broken by return

    else:

        print("This is not a valid username")
        print("Username should be between 6 and 20 letters")

        return False


def valid_pass(password):
    """
    Checks if password is valid
    """
    if len(password) >= 8 and len(password) <= 25 and password != "forgot":
        return True

    else:
        print("This is not a vaid password")
        print("Password should be between 8 and 25 letters")

        return False


def register_user(user_list):
    """
    Registers a new user
    """

    def db_register(username, password, ques, ans):
        """
        Registers the user and returns the user_id
        """
        global sql_cursor
        global users
        global database

        sql_cursor.execute(
            f'INSERT INTO users(username, password, question, answer) VALUES("{username}", "{password}, {ques}, {ans}");'
        )
        print("Saving ...")
        database.commit()
        sql_cursor.execute(f'SELECT user_id FROM users WHERE username="{username}";')

        return sql_cursor.fetchone()[0]

    while True:

        print("Enter the username you want")
        print("Type cancel if you want to cancel registering")

        username = input("Your Username : ")
        if username == "cancel":

            print("Canceling ...")
            return None

        if valid_user(username, user_list):

            while True:
                print("Enter the password you want")
                password = take_pass("Your Password : ")

                if valid_pass(password):
                    print("Confirm your password")
                    conf_pass = take_pass("Your Password : ")

                    if conf_pass == password:
                        print(
                            "Enter a personal question only you know the answer to which."
                        )
                        print(
                            "For Example, Name of your first pet, or Name of city you were born in, etc"
                        )

                        ques = input("Your question : ")
                        ans = take_pass("Your answer : ")

                        user_id = db_register(username, password, ques, ans)
                        print(f"You are now registered with user id {user_id}")

                        return username

                    else:
                        print("Your Passwords don't match.Try Again\n")


def do_user():
    """
    Main user menu
    """
    global user

    while True:

        print("*********************************************")
        print("Enter 1 to change username")
        print("Enter 2 to reset the password")
        print("Enter 3 to delete the account")
        print("Enter 4 to go back")
        print("*********************************************")
        print()

        do_user = input("Your Input : ")

        if do_user == "1":

            new_user = input("Enter new username : ")

            if valid_user(new_user, user):

                print("Are you sure you want to change the username?")
                s_ans = input("Your Answer (y/n) : ").lower()

                if s_ans == "y":

                    db_change(
                        "users", "username", new_user, f'username="{user["name"]}"'
                    )
                    user["name"] = new_user
                    print("Successfully changed the username")

                elif s_ans == "n":

                    print("Ok! then cancelling the change ...")

                else:
                    print("Invalid input try again")

        elif do_user == "2":

            reset_pass(user["name"], user["password"], user["ques"], user["ans"])

        elif do_user == "3":

            print("Are you sure you want to delete your user.")
            print("It will delete all your saved password.")
            print("Make sure you back up all your password before deleting them")

            while True:

                conf_del = input("Are you sure? (y/n) : ").lower()

                if conf_del == "y":

                    while True:

                        conf_pass = take_pass("Confirm your password : ")

                        if conf_pass == user["password"]:

                            delete_user(user["name"], user["id"])

                            break

                        else:
                            print("Invalid password.\nTry again.")

                elif conf_del == "n":

                    print("Cancelling Deletion ...")
                    break

                else:
                    print("Invalid input.\nTry again.\n")

        elif do_user == "4":

            break


def delete_user(username, user_id):
    """
    Deletes the user from database
    """
    global sql_cursor
    global database

    print("Are you absolutely sure that you want to delete your account.")
    conf_del = input("(y/n) : ").lower()

    if conf_del == "y":

        print("Deleting...")

        sql_cursor.execute(f"DELETE FROM passwords WHERE user_id={user_id};")
        sql_cursor.execute(f'DELETE FROM users WHERE username="{username}";')
        database.commit()

        print("Account successfully deleted")
        print("You need to start the program again")
        print("Exiting now")
        sleep(5)
        quit()

    else:
        print("Cancelling deletion ...")
        return


# Password Funcs


def show_all_service(pass_list):
    """
    Reads and prints all the services for user reference
    """
    service_list = []

    for pass_num in range(len(pass_list)):

        service_list.append(pass_list[pass_num][1])
        print(f"{pass_num + 1}. {pass_list[pass_num][1]}")

    return service_list


def find_pass(pass_list, service):
    """
    Returns the pass word from the list
    """
    for pass_info in pass_list:
        if pass_info[1] == service:
            return pass_info[2]


def delete_pass(service):
    """
    deletes a password
    """
    global passwords
    global sql_cursor
    global database

    while True:
        print(f"Are you sure you want to delete the password for {service}")
        conf = input("Confirmation (y/n) : ").lower()

        if conf == "y":

            sql_cursor.execute(f'DELETE FROM passwords WHERE service="{service}"')

            for num in range(len(passwords)):

                if passwords[num][1] == service:
                    passwords.pop(num)
                    break

            database.commit()
            break

        elif conf == "n":
            print("Cancelling deletion .. ")
            break

        else:
            print("Invalid input.")
            print("Try Again")


def add_new_pass(pass_list, user_id):
    """
    Adds a new password by taking input
    """

    new_service_entered = False
    add = True

    while add:

        if not new_service_entered:

            print("Enter what is the new password for?")
            new_service = input("Service : ")
            new_service_entered = True

        print()

        if check_ser_presence(new_service, pass_list):

            print("Enter the password you want to save.")
            new_pass = take_pass("Password : ")

            print()

            write_pass(new_service, new_pass, user_id)
            add = False

        else:

            print("This service already exists.")

            while True:

                print("Enter 1 to replace the older password")
                print("Enter 2 to change the service")
                print("Enter 3 to cancel the operation.")

                add_inp = input("Your input")

                if add_inp == "1":
                    delete_pass(new_service)
                    break

                elif add_inp == "2":
                    new_service_entered = False
                    break

                elif add_inp == "3":
                    add = False
                    break

                else:
                    print("Invalid command!")
                    print("Try Again")


def check_ser_presence(service, user_pass_list):
    """
    Returns True is service is not present
    """

    for pass_info in user_pass_list:
        if pass_info[1] == service:
            return False

    return True


def write_pass(service, password, user_id):
    """
    adds the service and passwords to the list
    """
    global sql_cursor
    global database
    global passwords

    query = f'INSERT INTO passwords(service,pass,user_id) values("{service}","{password}","{user_id}");'
    sql_cursor.execute(query)
    print("Saving ...")
    database.commit()

    passwords = fetch_data(sql_cursor, "passwords")

    print("Password saved successfully\n")


def update_service(pass_list, user_id):
    """
    Updates the service name
    """
    global sql_cursor
    global database
    global passwords

    print("Enter the name of old service")
    old_ser = input("Service : ")

    if check_ser_presence(old_ser, pass_list):
        print(f"{old_ser} is not saved yet.")

    else:
        print("Enter new service name")
        new_ser = input("New Service : ")

        if check_ser_presence(new_ser, pass_list):

            sql_cursor.execute(
                f'UPDATE passwords SET service="{new_ser}" WHERE service="{old_ser}" AND user_id="{user_id}";'
            )

            while True:

                print(f"Are you sure you want to change {old_ser} to {new_ser}")
                conf = input("Confirmation (y/n) : ").lower()

                if conf == "y":
                    database.commit()

                    for pass_num in range(len(passwords)):
                        if (
                            passwords[pass_num][1] == old_ser
                            and passwords[pass_num][3] == user_id
                        ):
                            passwords[pass_num][1] = new_ser

                    print()
                    break

                elif conf == "n":
                    print("Cancelling the change ...")
                    print()
                    break

                else:
                    print("\nInvalid input")
                    print("Try again\n")

        else:
            print(f"There already exists a password for {new_ser}.\n")


def update_password(pass_list, user_id):
    """
    Updates the password
    """
    global sql_cursor
    global database
    global passwords

    print("Enter the name service for which you want to change the password")
    service = input("Service : ")
    print()

    if check_ser_presence(service, pass_list):
        print(f"{service} is not saved yet.")

    else:
        print("Enter new password")
        password = take_pass("New Service : ")

        sql_cursor.execute(
            f'UPDATE passwords SET pass="{password}" WHERE service="{service}" AND user_id="{user_id}";'
        )

        while True:

            print(f"Are you sure you want to change the password for {service}")
            conf = input("Confirmation (y/n) : ").lower()

            if conf == "y":
                database.commit()

                passwords = fetch_data(sql_cursor, "passwords")
                print()
                break

            elif conf == "n":
                print("Cancelling the change ...")
                print()
                break

            else:
                print("\nInvalid input")
                print("Try again\n")


def generate_key():
    """
    Generates the key and save it into a file
    """
    # generating key
    key = Fernet.generate_key()

    key_dir = os.path.join(os.path.dirname(__file__), "resources/key")

    # writing key in file
    with open(key_dir, "wb") as keyFile:
        keyFile.write(key)


def load_key():
    """
    Loads the previously generated key
    """

    key_dir = os.path.join(os.path.dirname(__file__), "resources/key")

    try:
        return open(key_dir, "rb").read()
    except:
        return None


def encrypt_message(message):
    """
    Encryptes a string
    """

    # loading the key
    key = load_key()

    # encoding the message ie convetsion to bytes
    encoded_message = message.encode()

    # creating a fernet object
    f = Fernet(key)

    # encrypting the messsage
    encrypted_message = f.encrypt(encoded_message)

    return str(encrypted_message, "utf-8")


def decrypt_message(encrypted_message):
    """
    Decrypts the encrypted message
    """

    # conversion to bytes
    encrypted_message = bytes(encrypted_message, "ascii")

    # loading key
    key = load_key()

    # creating a fernet object
    f = Fernet(key)

    # decrypting the messsage
    decrypted_message = f.decrypt(encrypted_message)

    return decrypted_message.decode()


if __name__ == "__main__":

    with open("password.txt") as pass_file:
        mysql_db_pass = pass_file.read()

    # initiating mysql
    database = sql_connect(
        host="localhost", user="root", password=mysql_db_pass, database="safepass"
    )
    sql_cursor = database.cursor()

    users, passwords = fetch_data(sql_cursor, "users", "passwords")
    pref = get_preferences()

    user = login(users)

    # Main Loop
    while True:

        user_pass_list = []

        for pass_list in passwords:
            if pass_list[3] == user["id"]:
                user_pass_list.append(pass_list)

        print("*********************************************")
        print("Enter 1 to view a password")
        print("Enter 2 to delete a password")
        print("Enter 3 to add a new password")
        print(
            "Enter 4 to view all saved passwords \n"
            "\t(This will only show what is password saved for.)"
        )
        print("Enter 5 to update a password")
        print("Enter 6 for user related things")
        print("Enter 7 to exit")
        print("*********************************************")
        print()

        do = input("Your Input : ")

        if do == "1":

            print("\n******************************************************")
            service_list = show_all_service(user_pass_list)
            print("******************************************************")
            print()

            print("Which password do you want to see?")
            service_input = input("Your input : ")

            if service_input in service_list:
                print()
                pyperclip.copy(find_pass(user_pass_list, service_input))
                print(
                    "Your password has been copied. \nJust go ahead and pase it where you want."
                )
                print()

            else:
                try:
                    service_num = int(service_input)

                    if service_num <= len(service_list):
                        print()
                        pyperclip.copy(user_pass_list[service_num - 1][2])
                        print(
                            "Your password has been copied. \nJust go ahead and pase it where you want."
                        )
                        print()

                    else:
                        print("There is no password saved for this.")
                        print("See the above list for your saved passwords.")
                        print()

                except:
                    print("There is no password saved for this.")
                    print("See the above list for your saved passwords.")
                    print()

        elif do == "2":

            print("******************************************************")
            service_list = show_all_service(user_pass_list)
            print("******************************************************")
            print()

            print("Which password do you want to delete")
            delPass = input("Your Input : ")

            if delPass in service_list:
                delete_pass(delPass)
            else:
                print("\n There is no password saved for this.")
                print("See the list for your saved passwords")
            print()

        elif do == "3":

            add_new_pass(user_pass_list, user["id"])

        elif do == "4":
            print("\n******************************************************")
            show_all_service(user_pass_list)
            print("******************************************************")
            print()

        elif do == "5":
            up_pass = None

            print("\n******************************************************")
            show_all_service(user_pass_list)
            print("******************************************************")
            print()

            while True:

                print("Enter 1 if you want to update service name")
                print("Enter 2 if you want to update password")
                print("Enter 3 to view all saved passwods")
                print("Enter 4 to go back")
                print()

                update = input("Your input : ")

                if update == "1":
                    update_service(user_pass_list, user["id"])

                elif update == "2":
                    update_password(user_pass_list, user["id"])

                elif update == "3":
                    print("\n******************************************************")
                    show_all_service(user_pass_list)
                    print("******************************************************")
                    print()

                elif update == "4":
                    print()
                    break

        elif do == "6":

            print("Confirm your user password")
            conf_password = take_pass("Your Password : ")

            if conf_password == user["password"]:

                do_user()

            else:
                print("Invalid Password!\n")

        elif do == "7":
            break

        else:
            print("\nInvalid Input.\nTry Again.\n")

    # Clearing up the program
    database.close()
    quit()
