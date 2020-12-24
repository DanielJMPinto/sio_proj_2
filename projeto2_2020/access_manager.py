import json
import argparse
from utils import ACCESS_FILE


def get_access_list():
    with open(ACCESS_FILE, 'r') as file:
        data = json.load(file)
    return data

def save_access_list(data):
    with open(ACCESS_FILE, 'w') as file:
        json.dump(data, file)
    print("Access list saved with success")

def main(args):
    data = get_access_list()

    if args.add_user:
        new_user = input("User name: ")
        if new_user in data:
            print("This user already is in access list")
            return

        give_access = input(f"Give access to transfering files to {new_user}? (y/N) ")
        data[new_user] = {"send": give_access == 'y'}

        save_access_list(data)
    elif args.remove_user:
        user_remove = input("User name: ")
        if user_remove not in data:
            print("This user doesn't exist in access list")
            return

        del data[user_remove]

        save_access_list(data)
    elif args.change_access:
        user = input("User name: ")
        if user not in data:
            print("This user doesn't exist in access list")
            return

        choice = input(
            f"Choose one of those options:\n" \
            "1) Remove transfer access\n" \
            "2) Add transfer access\n" \
            "> "
        )
        
        if not choice.isdigit() or int(choice) not in [1, 2]:
            print("Invalid option")
            return

        choice = int(choice)
        data[user]["send"] = choice == 2

        save_access_list(data)
    elif args.see_list:
        for user in data:
            print(f"{user} -> access = {data[user]['send']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage users access.")

    parser.add_argument("-a", "--add_user", help="Add new user to the access list", action="store_true")
    parser.add_argument("-r", "--remove_user", help="Remove user from access list", action="store_true")
    parser.add_argument("-c", "--change_access", help="Change user access", action="store_true")
    parser.add_argument("-s", "--see_list", help="See access list", action="store_true")

    args = parser.parse_args()
    main(args)