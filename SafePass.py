# Imports
from cryptography.fernet import Fernet
import pyperclip
import getpass
import time
import os

# All the files
BASE_DIR = os.path.dirname(__file__)
RESOURCE_DIR = os.path.join(BASE_DIR, "resources/mainfile")
PASS_DIR = os.path.join(RESOURCE_DIR, 'main.txt')
USER_DIR = os.path.join(RESOURCE_DIR, 'users.txt')
KEY_DIR = os.path.join(RESOURCE_DIR, "key.key")


# Main Functions


def check_for_files():
    """
    check if the files are present
    """

    # pass dir
    try:

        f = open(PASS_DIR)

    except FileNotFoundError or FileExistsError:

        print(f"{PASS_DIR} should be there")
        print("The FILE NOT FOUND. Please check or contact Karanjot Singh")
        input("Press any key to exit.")
        quit()

    finally:

        f.close()

    # user dir
    try:

        f = open(USER_DIR)

    except FileNotFoundError or FileExistsError:

        print(f"{USER_DIR} should be there")
        print("The FILE NOT FOUND. Please check or contact Karanjot Singh")
        input("Press any key to exit.")
        quit()

    # key dir
    try:

        f = open(KEY_DIR)

    except FileNotFoundError or FileExistsError:

        print(f"{KEY_DIR} should be there")
        print("The FILE NOT FOUND. Please check or contact Karanjot Singh")
        input("Press any key to exit.")
        quit()

    finally:

        f.close()


def register():
    """
    Registers a new user
    """

    print("Enter a password which you want to set up to open app.")
    time.sleep(2)  # to emphasis
    print("This password will be asked whnever you enter the program.")
    time.sleep(2)  # to emphasis
    print("REMEMBER THIS PASSWORD. This is your master password.")
    time.sleep(2.5)  # to emphasis

    # loop for password
    while True:

        # taking input for password
        password = input("Your Password : ")
        confpassword = input("Confirm your password : ")

        # check if passwords are same
        if password == confpassword:

            # opening file and writing the master password in user file
            with open(USER_DIR, "w") as userFile:
                userFile.write(encrypt_message(password) + '\n')
            print(
                "Congratulations you are registered seccesfully. Now you can start saving your passwords.")

            # This return is just to break the loop and exit the function
            return

        # an infinite loop until user enters correct password
        else:
            print("Your Passwords do not match")


def authorise():
    """
    Traps user in loop untill correct password is not entered
    """

    # opening and reading the master password
    with open(USER_DIR, "r") as userFile:
        line = userFile.read().replace("\n", "")

    # checking for mew user ie seeing if no master password is saved
    if line == "0":

        # Remove all passwords just for security
        with open(PASS_DIR, "w") as passFile:
            passFile.write("")

        # Generate a new key to encrypt
        generate_key()

        # Register User
        register()

    # if user is already using the program
    else:

        while True:

            # asking for password (getpass is just so that password is hidden)
            password = getpass.getpass(prompt="Enter the password : ")

            # Matching the password
            if password == decrypt_message(line):

                print("Password matched!\nWelcome\n")
                # This return is just to break the loop and exit the function
                return

            else:

                print("Incorrect password.\nTry Again.\n")


def check_service_presence(service):
    """
    Returns True is service is not present
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        # Traverses through the list
        for line in allpasslst:

            # Makes the list of service and checks for repeat
            passInfo = line.split(", ")

            # passInfo[0] is service name
            if decrypt_message(passInfo[0]) == service:
                return False

        return True


def check_service_num_presence(service_num):
    """
    Returns True if there is a service corr to the number
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        if service_num <= len(allpasslst):
            return True
        else:
            return False


def write_pass():
    """
    Takes input from user,
    and appends the file with password.
    """

    newserviceEntered = False

    while True:

        # to prevent reprtition of asking this again
        if not(newserviceEntered):

            # Taking service served by password as input
            print("Enter what is the new password for?")
            newservice = input("Your input : ")
            newserviceEntered = True

        print()

        # to prevent repitition
        if check_service_presence(newservice):

            # Taking the password as input
            print("Enter the password you want to save.")
            newPass = input("Your input : ")

            print()

            # Making a list and converting into str which will entered as text
            passlst = [encrypt_message(newservice), encrypt_message(newPass)]
            passstr = ", ".join(passlst)

            # Opening the file for appending in read text mode
            try:

                with open(PASS_DIR, "a") as passFile:
                    passFile.write(passstr + "\n")

            except Exception:

                print("Unable to save password")

            print("Successfully saved the password\n")
            break

        # if the password for service already exists
        else:

            print("This service of password already exists")

            while True:
                # ask to replace
                print("Do you want to replace the older one?")
                delete_input = input("Your input (y/n) : ").lower()

                if delete_input == "y":

                    # delete the old one and continue
                    delete_pass(newservice)
                    break

                elif delete_input == "n":

                    # ask to change the new service
                    print("Then might like to change the service")

                    # to enable to ask again to enter the service
                    newserviceEntered = False
                    break

                else:

                    print("Invalid Command\nTry Again\n")


def show_all_service():
    """
    Reads and prints all the services for user reference
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        # Traverses through the list
        for index, line in enumerate(allpasslst):

            # Makes the list of service and password and print it
            passInfo = line.split(", ")
            print(f"{ index+1 }. { decrypt_message(passInfo[0]) }")


def no_of_pass():
    """
    Returns the number of passwords saved
    """

    with open(PASS_DIR, "r") as passFile:
        return len(passFile.readlines())


def show_pass(service):
    """
    returns the password of service entred in decrypted form
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        # Traverses through the list
        for line in allpasslst:

            try:
                # Makes the list of service and password and return password
                passInfo = line.split(", ")
                if decrypt_message(passInfo[0]) == service:
                    return decrypt_message(passInfo[1])

            except Exception as e:
                print(e)
                print(line)


def show_pass_by_num(num):
    """
    Returns the password corr to a number
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        try:
            passInfo = allpasslst[num-1].split(", ")
            return decrypt_message(passInfo[1])

        except Exception as e:
            print(e)
            print(num-1)


def show_username_by_num(num):
    """
    Returns the password corr to a number
    """

    # Opens the file for reading
    with open(PASS_DIR, "r") as passFile:

        # converts all the lines into a list
        allpasslst = passFile.readlines()

        try:
            passInfo = allpasslst[num-1].split(", ")
            return decrypt_message(passInfo[0])

        except Exception as e:
            print(e)
            print(num-1)


def delete_pass(service):
    """
    Deletes the password and service of service entered
    """

    # check for presence of service
    if not check_service_presence(service):

        # Opening the file
        with open(PASS_DIR, "r") as passFile:

            # putting file content in a list
            lines = passFile.readlines()

        # Traversing the lines
        for index, line in enumerate(lines):

            # Separating service and password in list
            passInfo = line.split(", ")

            # Finding and deleting the service
            if decrypt_message(passInfo[0]) == service:
                del lines[index]

        # Writing the resultant list in the file
        with open(PASS_DIR, "w") as passFile:
            passFile.writelines(lines)

    else:

        print("service is already not there")


def generate_key():
    """
    Generates the key and save it into a file
    """
    # generating key
    key = Fernet.generate_key()

    # writing key in file
    with open(KEY_DIR, "wb") as keyFile:
        keyFile.write(key)


def load_key():
    """
    Loads the previously generated key
    """

    return open(KEY_DIR, "rb").read()


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

    return str(encrypted_message, 'utf-8')


def decrypt_message(encrypted_message):
    """
    Decrypts the encrypted message
    """

    # conversion to bytes
    encrypted_message = bytes(encrypted_message, 'ascii')

    # loading key
    key = load_key()

    # creating a fernet object
    f = Fernet(key)

    # decrypting the messsage
    decrypted_message = f.decrypt(encrypted_message)

    return decrypted_message.decode()


def update_password(service):
    """
    Update the password and service of service entered
    """

    # check for presence of service
    if not check_service_presence(service):

        # Opening the file
        with open(PASS_DIR, "r") as passFile:

            # putting file content in a list
            lines = passFile.readlines()

        # Traversing the lines
        for index, line in enumerate(lines):

            # Separating service and password in list
            passInfo = line.split(", ")

            # Finding and deleting the service
            if decrypt_message(passInfo[0]) == service:

                while True:

                    # asking user what to do
                    print("\nEnter 1 to change service")
                    print("Enter 2 to change password\n")
                    inp = input("Your Input : ")

                    # chnging service name
                    if inp == "1":
                        ser = input("Enter the new name for service : ")
                        passInfo[0] = encrypt_message(ser)
                        print("Name of service changed.")
                        done = True

                    # changing service password
                    elif inp == "2":
                        passw = input("Enter the new password : ")
                        passInfo[1] = encrypt_message(passw)
                        print("Password changed")
                        done = True

                    # else for invalid input
                    else:
                        print("\nInvalid input. Try Again\n")
                        done = False

                    # will only execute once password is changed
                    if done:
                        print("\nEnter 1 to exit")
                        print("Enter anything else to still change something")
                        again = input("Your input : ")

                        if again == "1":

                            # writing to lines list
                            lines[index] = ",".join(passInfo)
                            print()

                            # Writing the resultant list in the file
                            with open(PASS_DIR, "w") as passFile:
                                passFile.writelines(lines)

                                # This return is just to break the loop and exit the function
                                return

    else:

        print("service is not there")


if __name__ == "__main__":

    # The main code execution starts here

    # Checking if all the neccessary files are available
    check_for_files()

    # Welcome text
    print()
    print("Welcome to SafePass v1.1. The Ultimate password manager.")
    print("Now you don't need to remember multiple passwords. Only remember one password and view all your passwords with it only.")
    print("All your passwords here are encrypted, so you don't need to worry if someone opened your your file.\n")

    time.sleep(3)

    authorise()

    time.sleep(1)

    print("*********************************************")
    print(f"You have {no_of_pass()} passwords saved.\n")
    print("*********************************************")

    print()

    time.sleep(1)

    while True:

        print("*********************************************")
        print("Enter 1 to view a password")
        print("Enter 2 to delete a password")
        print("Enter 3 to add a new password")
        print("Enter 4 to view all saved passwords \n"
              "\t(This will only show what is password saved for.)")
        print("Enter 5 to update a password")
        print("Enter Ctr + c to exit anytime")
        print("*********************************************")
        print()

        time.sleep(2)

        do = input("Your input : ")

        if do != "1" and do != "2" and do != "3" and do != "4" and do != "5":
            print("Invalid Input.\nTry Again")

        elif do == "1":

            print("You chose to view a password.")

            time.sleep(1)

            print("\n******************************************************")
            show_all_service()
            print("******************************************************")
            print()

            time.sleep(1)

            print("Which password do you want to see?")
            userservice = input("Your input : ")

            try:
                usernum = int(userservice)

                if check_service_num_presence(usernum):

                    print()
                    pyperclip.copy(show_pass_by_num(usernum))
                    print(
                        f"The password for '{show_username_by_num(usernum)}' has been copied to your clipboard.")
                    print("Just go ahead and paste it.")
                    print()

                    time.sleep(3)

                else:
                    print("There is no password saved for this.")
                    print("See the above list for your saved passwords.")
                    print()

            except:

                if (not check_service_presence(userservice)):

                    print()
                    pyperclip.copy(show_pass(userservice))
                    print(
                        f"The password for '{userservice}' has been copied to your clipboard.")
                    print("Just go ahead and paste it.")
                    print()

                    time.sleep(3)

                else:
                    print("There is no password saved for this.")
                    print("See the above list for your saved passwords.")
                    print()

        elif do == "2":

            print("You chose to delete a password.")

            time.sleep(1)

            print("******************************************************")
            show_all_service()
            print("******************************************************")
            print()

            time.sleep(1)

            print("Which password do you want to delete")
            delPass = input("Your Input : ")

            delete_pass(delPass)

            print()

        elif do == "3":
            print("You chose to enter a new password.\n")

            time.sleep(1)

            write_pass()

        elif do == "4":
            print("******************************************************")
            show_all_service()
            print("******************************************************")
            print()

        elif do == "5":
            print("You chose to update a password")

            time.sleep(1)

            print("******************************************************")
            show_all_service()
            print("******************************************************")
            print()

            time.sleep(1)

            print("Which password do you want to update")
            updPass = input("Your Input : ")

            update_password(updPass)

        else:
            print("Some error occured")
            input("Press enter to exit")
            quit()
