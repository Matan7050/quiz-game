import socket
import time
import threading
import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import csv

key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'

SUCCESSFLAG = "accept"
FORMAT = 'utf-8'
response = "Wrong"
points = 0
username = ""
scoring_points = 0
Countdown=0
score = [0] * 2
connected = 1
respond = 'a'
string_of_scores = ''
no_clients_A = 0
no_clients_B = 0
global Letter
global selected_time

SERVER_IP = '127.0.0.1'  # Replace with the server's IP address
SERVER_PORT = 1200  # Replace with the server's port

# Function to close the application window
def close_the_window():
    print("We closed the window")
    exit(0)

# Function to handle server disconnection
def Server_disconnect():
    print("Please try again later")
    exit(0)

# Function to send an encrypted message to the server
def send_message(message):
    try:
        start_time = time.time()
        while True:
            data = encrypt(message)
            client_socket.send(data)
            time.sleep(0.01)
            msg = client_socket.recv(1024)
            if msg == data:
                client_socket.send(encrypt(SUCCESSFLAG))
                return
    except ConnectionResetError:
        raise Exception("[COMUNICATION WITH SERVER LOST]")

# Function to receive and decrypt a message from the server
def receive_message():
    try:
        while True:
            data = client_socket.recv(1024)
            client_socket.send(data)
            test = client_socket.recv(1024)
            if test == encrypt(SUCCESSFLAG):
                return decrypt(data)

    except ValueError:
        raise Exception("[PROBLEM COMMUNICATING WITH SERVER]")
    except ConnectionResetError:
        raise Exception("[COMUNICATION WITH SERVER LOST]")

# Function to decrypt a ciphertext using AES encryption
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode(FORMAT)

# Function to encrypt a plaintext using AES encryption
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to get the password and username from the user
def get_password():
    global respond, connected,username
    entered_password = password_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    send_message(entered_password)
    print(f"Entered password: {entered_password}")
    respond = receive_message()
    # Check if the username already exists
    if username_exists(username):
        print("Username already exists. Please choose a different username.")
        respond = "incorrect password"
    else:
        print("Thats good Nickname!")

    if respond == "incorrect password":
        pass_window.destroy()  # Close the window
    else:
        connected = False  # Break the while loop
        # Insert the user into the CSV file
        insert_user_into_csv(username)
        print("Username:", username)
        print("Password:", password)
        pass_window.destroy()

# Function to display the leaderboard
def display_leaderboard(formatted_scores):
    segments = formatted_scores.split(':')
    print(formatted_scores)
    first =True
    # Create a new Tkinter window for the leaderboard
    leaderboard_window = tk.Tk()
    leaderboard_window.title("Leaderboard")
    leaderboard_window.geometry("850x450")
    leaderboard_window.configure(bg="purple")
    result = []

    for i in range(0, len(segments), 2):
        if i + 1 < len(segments):
            key = segments[i]
            try:
                value = int(segments[i + 1])
                result.append((key, value))
            except ValueError:
                print(f"Invalid points value at index {i + 1}")
        else:
            print(f"Warning: Incomplete segment at index {i}")

    # Create a title label
    title_label_text = "Our Leaders"
    title_label = tk.Label(leaderboard_window, text=title_label_text,bg = "purple",fg = "white", font=("Arial", 14, "bold"))
    title_label.pack(pady=10)
    # Print the result and create a label for each entry
    for key, value in result:
        if first:
            label_text = f"{key}                                   {value} points"
            label = tk.Label(leaderboard_window, text=label_text, bg="white", fg="black", font=("Arial", 15))
            label.pack(pady=5)
            first =False
        else:
            print(f"{key} with {value} points")
            label_text = f"{key}                                   {value} points"
            label = tk.Label(leaderboard_window, text=label_text,bg ="purple",fg ="white",font=("Arial", 15))
            label.pack(pady=5)

    # Close the window after 4 seconds
    leaderboard_window.after(4000, leaderboard_window.destroy)

    # Run the Tkinter main loop for the leaderboard window
    leaderboard_window.mainloop()

# Function to start a countdown timer
def Start_timer(Timer):
    global Choice
    global Countdown
    Countdown = Timer
    Countdown = Countdown * 100
    while Countdown >= 0:
        if not Choice == '4':
            question_window_root.destroy()
            return ()
        try:
            Timer_label.config(text=Countdown)
        except:
            exit(0)
        if Countdown == 0:
            print("Times up!")
            question_window_root.destroy()  # Close the windowwhen the countdown timer finishes
            return ()
        else:
            Countdown -= 1
            time.sleep(0.01)

    return ()

# Function to select an option for a question
def Select_option(Answer,Options):
    global Choice
    Choice = Answer
    print("Answer selected:", Options[int(Answer)])
    return()

# Function to select a category for the quiz
def select_category(category):
    global selected_category
    selected_category = category
    print("Selected category:", selected_category)
    root_select_category.destroy()

# Function to check if a username already exists in the database
def username_exists(username):
    try:
        with open('username_db.csv', mode='r') as file:
            reader = csv.reader(file)
            # Iterate through usernames without creating a full list
            for row in reader:
                if username == row[0]:
                    return True
            return False  # Username not found in the loop

    except FileNotFoundError:
        print(f"Error: CSV file 'username_db.csv' not found.")
        return False

# Function to insert a user into the CSV file
def insert_user_into_csv(username):
    with open('username_db.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username])

# Function to get the number of players for a category
def get_num():
    global no_clients_A, no_clients_B, topic
    if topic == 'A':
        no_clients_A = host_entry.get()
        send_message(no_clients_A)
        host.destroy()
        return
    if topic == 'B':
        no_clients_B = host_entry.get()
        send_message(no_clients_B)
        host.destroy()
        return

# Function to display the top 5 leaders
def show_top_5_leaders(leaders_file_path):
    try:
        # Read the leaders file
        with open(leaders_file_path, 'r', newline='') as file:
            reader = csv.reader(file)
            # Sort leaders based on scores in descending order
            sorted_leaders = sorted(reader, key=lambda x: int(x[1]), reverse=True)
            # Retrieve the top 5 leaders
            top_5_leaders = sorted_leaders[:5]

        # Print the top 5 leaders for debugging
        print("Top 5 Leaders:")
        for i, leader in enumerate(top_5_leaders):
            print(f"{i + 1}. {leader[0]}: {leader[1]} points")

        # Create a new Tkinter window for displaying leaders
        leaders_window = tk.Tk()
        leaders_window.title("Top 5 Leaders of All Time")
        leaders_window.geometry("500x500")
        leaders_window.configure(bg="purple")
        leaders_window.protocol("WM_DELETE_WINDOW", close_the_window)

        # Create and place labels for each leader
        for i, leader in enumerate(top_5_leaders):
            label_text = f"{i + 1}. {leader[0]}: {leader[1]} points"
            label = tk.Label(leaders_window, text=label_text, font=("Arial", 12))
            label.pack(pady=5)

        # Run the Tkinter main loop for the leaders window
        leaders_window.mainloop()

    except FileNotFoundError:
        print(f"Error: Leaders file '{leaders_file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")

# Function to display the winners of the quiz
def the_winners(formatted_scores):
    segments = formatted_scores.split(':')
    print(formatted_scores)
    first = True
    # Create a new Tkinter window for the leaderboard
    leaderboard_window = tk.Tk()
    leaderboard_window.title("Leaderboard")
    leaderboard_window.geometry("850x450")
    leaderboard_window.configure(bg="lightblue")
    result = []

    for i in range(0, len(segments), 2):
        if i + 1 < len(segments):
            key = segments[i]
            try:
                value = int(segments[i + 1])
                result.append((key, value))
            except ValueError:
                print(f"Invalid points value at index {i + 1}")
        else:
            print(f"Warning: Incomplete segment at index {i}")

    # Create a title label
    title_label_text = "Our Leaders"
    title_label = tk.Label(leaderboard_window, text=title_label_text, bg="purple", fg="white",font=("Arial", 14, "bold"))
    title_label.pack(pady=10)
    # Print the result and create a label for each entry
    for key, value in result:
        if first:
            # Remove the index part from the key for the first place winner
            name = key.split('.')[1] if '.' in key else key
            label_text = f"      The Winner is {name} with {value} points        "
            label = tk.Label(leaderboard_window, text=label_text, bg="yellow", fg="black", font=("Arial", 15))
            label.pack(pady=5)
            first = False
        else:
            print(f"{key} with {value} points")
            label_text = f"{key}                                   {value} points"
            label = tk.Label(leaderboard_window, text=label_text, bg="lightblue", fg="black", font=("Arial", 15))
            label.pack(pady=5)

    # Close the window after 4 seconds
    leaderboard_window.after(10000, leaderboard_window.destroy)

    # Run the Tkinter main loop for the leaderboard window
    leaderboard_window.mainloop()

while connected:

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
     # Create the main window
    pass_window = tk.Tk()
    pass_window.title("Password & Nickname Entry")
    pass_window.protocol("WM_DELETE_WINDOW", close_the_window)
    # Create and place the frame for username
    username_frame = tk.Frame(pass_window)
    username_frame.pack(pady=10)

    username_label = tk.Label(username_frame, text="Username:")
    username_label.pack(side=tk.LEFT, padx=10)

    username_entry = tk.Entry(username_frame)
    username_entry.pack(side=tk.LEFT, padx=10)

    # Create and place the frame for password
    password_frame = tk.Frame(pass_window)
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Password:")
    password_label.pack(side=tk.LEFT, padx=10)

    password_entry = tk.Entry(password_frame, show="*")
    password_entry.pack(side=tk.LEFT, padx=10)

    # Create and place the submit button
    submit_button = tk.Button(pass_window, text="Submit", command=get_password)
    submit_button.pack(pady=20)

    # Run the main loop
    try:
        # Start the main loop
        pass_window.mainloop()
    except KeyboardInterrupt:
        # Handle the KeyboardInterrupt (e.g., perform cleanup)
        print("Program interrupted. Cleaning up...")
        # Add any cleanup code here if needed
        pass_window.destroy()

root_select_category = tk.Tk()
root_select_category.geometry("800x450")
root_select_category.title("Category Selection")
root_select_category.configure(bg="purple")
root_select_category.protocol("WM_DELETE_WINDOW", close_the_window)

label = tk.Label(root_select_category, text="Which category do you want?", font=("Arial", 15), bg="purple", fg="white")
label.grid(row=0, column=0, columnspan=2, pady=10)

# Create buttons for each category in columns with light blue background
button_a = tk.Button(root_select_category, text="History", font=("Arial", 18, "bold"), command=lambda: select_category('A'), bg="lightblue", width=25, height=5)
button_a.grid(row=80, column=0, padx=5, pady=5)

button_b = tk.Button(root_select_category, text="Technology", font=("Arial", 18, "bold"), command=lambda: select_category('B'), bg="lightblue", width=25, height=5)
button_b.grid(row=80, column=1, padx=5, pady=5)

# Create a button for "Top Five Leaders" in a new row with yellow background
button_top_five = tk.Button(root_select_category, text="Top Five Leaders", font=("Arial", 18, "bold"),command=lambda: select_category('C'), bg="yellow", width=25, height=5)
button_top_five.grid(row=82, column=0, columnspan=2, pady=5)

root_select_category.mainloop()


topic = selected_category

if topic == 'C':
    show_top_5_leaders('winners.csv')
try:
    send_message(topic)
    print("the topic sent ok")
except:
    print("topic send fail")
    Server_disconnect()

try:
    num_of_players = int(receive_message())
    print(f"Number of players is {num_of_players}")
except:
    print("problem in recieve number of players")
    Server_disconnect()
try:
    send_message(username)
    print(f"The username {username} sent")
except:
    print("problem in sending username")
    Server_disconnect()
try:
    client_id = receive_message()
    print(f"Connected to the server as Client {client_id}")
    if client_id == "1":
        host = tk.Tk()
        host.geometry("850x450")
        host.title("Host")
        host.configure(bg="purple")
        host.protocol("WM_DELETE_WINDOW", close_the_window)
        label = tk.Label(host, text="How much players will play??", font=("Arial", 15))
        label.pack(pady=10)

        # Create and place the frame for password
        host_farme = tk.Frame(host)
        host_farme.pack(pady=10)

        host_label = tk.Label(host_farme, text="Number of players:")
        host_label.pack(side=tk.LEFT, padx=10)

        host_entry = tk.Entry(host_farme)
        host_entry.pack(side=tk.LEFT, padx=10)

        # Create and place the submit button
        submit_button = tk.Button(host, text="Submit", command=get_num)
        submit_button.pack(pady=20)

        host.mainloop()
except:
    print("problem in recieve client id")
    Server_disconnect()

quiz_finished = False
first_leader_board = False
while not quiz_finished:
    # Receive question and options from the server
    try:
        question = receive_message()
        print(f"Question received: {question}")
    except:
        print("Failed to receive question")
        Server_disconnect()

    if question == "end":
        try:
            print("we finished!")
            last_message = receive_message()
        except:
            print("Failed to receive final message")
            Server_disconnect()
        the_winners(string_of_scores)
        close_the_window()
    else:
        try:
            options_str = receive_message()
        except:
            print("options not recieved")
            Server_disconnect()
            display_leaderboard_thread2 = threading.Thread(target=display_leaderboard, args=(string_of_scores,)).start()
            time.sleep(5)
            break

    options_str = options_str.replace('[', "")
    options_str = options_str.replace(']', "")
    options = options_str.split(',')
    if first_leader_board:
        display_leaderboard(string_of_scores)
    first_leader_board =True

    question_window_root = tk.Tk()
    question_window_root.geometry("850x450")
    question_window_root.title("Kahoot! Question")
    question_window_root.configure(bg="purple")  # Set background color
    question_label = tk.Label(question_window_root, text=question, font=("Arial", 15), bg="lightblue", pady=10)
    question_label.grid(row=2, column=0, columnspan=2, sticky="W")
    question_window_root.protocol("WM_DELETE_WINDOW", close_the_window)

    # Create buttons 'a', 'b', 'c', and 'd' with corresponding commands
    button_a = tk.Button(question_window_root, text=options[0], font=("Arial", 15, "bold"),command=lambda: Select_option('0', options), bg="darkblue", fg="white", width=30, height=5)
    button_b = tk.Button(question_window_root, text=options[1], font=("Arial", 15, "bold"),command=lambda: Select_option('1', options), bg="darkgreen", fg="white", width=30, height=5)
    button_c = tk.Button(question_window_root, text=options[2], font=("Arial", 15, "bold"),command=lambda: Select_option('2', options), bg="darkred", fg="white", width=30, height=5)
    button_d = tk.Button(question_window_root, text=options[3], font=("Arial", 15, "bold"),command=lambda: Select_option('3', options), bg="darkorange", fg="white", width=30, height=5)

    # Use the grid geometry manager to arrange buttons in two columns
    button_a.grid(row=80, column=0, pady=5, padx=5)
    button_b.grid(row=80, column=1, pady=5, padx=5)
    button_c.grid(row=81, column=0, pady=5, padx=5)
    button_d.grid(row=81, column=1, pady=5, padx=5)

    Timer_label = tk.Label(question_window_root, text="10", font=("Arial", 20))
    # Place the timer label in the top-right corner using grid
    Timer_label.grid(row=0, column=2, columnspan=1, sticky="NE", pady=10)

    Choice = '4'
    Start_timer_thread = threading.Thread(target=Start_timer, args=(10,)).start()
    question_window_root.mainloop()

    Countdown = str(Countdown)
    try:
        send_message(str(Countdown))
    except:
        print("problem in sending points")
        Server_disconnect()
    try:
        send_message(str(Choice))
    except:
        print("the try to sen answer failed")
        Server_disconnect()
    try:
        Answer = receive_message()
    except:
        print("The answer fail")
        Server_disconnect()

    print(f"correct answer is: {Answer}")
    number_of_answer = 5
    if Answer == 'a':
        number_of_answer = 0
    if Answer == 'b':
        number_of_answer = 1
    if Answer == 'c':
        number_of_answer = 2
    if Answer == 'd':
        number_of_answer = 3
    if number_of_answer == int(Choice):
        Message = "Your'e Correct!"
        Color = 'green1'
    else:
        Message = "Maybe next time..."
        Color = 'red1'
    try:
        string_of_scores = receive_message()
        print(string_of_scores)
    except:
        print("the string didnt make it")
    string_to_end_question = f"The results will appear in a few moments"
    question_window_result = tk.Tk()
    question_window_result.geometry("850x450")
    question_window_result.title("Results")
    question_window_result.configure(bg="purple")
    question_label = tk.Label(question_window_result, text=question, font=("Arial", 15), bg="lightblue")
    question_label.pack(side="top", pady=10)
    question_window_result.protocol("WM_DELETE_WINDOW", close_the_window)

    question_label = tk.Label(question_window_result, text=Message, font=("Arial", 20), bg=Color)
    question_label.pack(side="top", pady=10)
    question_label = tk.Label(question_window_result, text=string_to_end_question, bg="purple",fg ="white" , font=("Arial", 20))
    question_label.pack(side="top", pady=10)

    question_window_result.after(3000, lambda: question_window_result.destroy())
    question_window_result.mainloop()

client_socket.close()
