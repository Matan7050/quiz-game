import threading
import time
import csv
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'

FORMAT = 'utf-8'
no_clients_A = 0
no_clients_B = 0
first1 =False
first2 =False
SERVER_PORT = 1200
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = SERVER_PORT
s.bind(('', port))
s.listen(max(no_clients_A,no_clients_B))
SUCCESSFLAG = "accept"
username = ''
ClientIn = []
players_waiting_room_FG = []
players_waiting_room_SG = []
client_usernames = {}

# Function to send an encrypted message to a client
def send_message(connection, message):
    while True:
        data = encrypt(message)
        connection.send(data)
        time.sleep(0.1)
        msg = connection.recv(1024)
        if msg == data:
            connection.send(encrypt(SUCCESSFLAG))
            return

# Function to receive and decrypt a message from a client
def receive_message(connection):
    while True:
        try:
            data = connection.recv(1024)
            time.sleep(0.1)
            connection.send(data)
            test = connection.recv(1024)
            if test == encrypt(SUCCESSFLAG):
                return decrypt(data)
        except ConnectionResetError:
            # Handle the case when the client disconnects
            print("Client disconnected.")
            return None

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

# Function to handle password authentication for clients
def password(ClientS):
    global username
    try:
        password = receive_message(ClientS)
        print("you got a new password from new client")
    except:
        print("there was a try to get password, that not succeed")
        return()
    with open('authenticator.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if password == row[0]:
                try:
                    send_message(ClientS, "password authenticated")
                    print("the password sent(correct)")
                except:
                    print("there was problem by sending the password")
                    return()
                connect(ClientS)
                return ()
        try:
            print("the password sent(incorrect)")
            send_message(ClientS, "incorrect password")
        except:
            print("there was problem by sending the password")
            return ()

# Function to establish a connection with a client and assign them to a quiz room
def connect(Client_w):
    global players_waiting_room_FG, players_waiting_room_SG,first1,first2,no_clients_A,no_clients_B
    print(f"Connection has been established to client")
    Ctopic = receive_message(Client_w)
    if Ctopic == 'A':
        try:
            players_waiting_room_FG.append(Client_w)
            number_of_players_FG = len(players_waiting_room_FG)
            print("added new player to History Quiz game")
        except:
            print("error by trying to enter the room")
            return()
        try:
            send_message(Client_w, str(number_of_players_FG))
            print("the number of the client sent")
        except:
            print("there was error by sending the number of the player")
            return()
        try:
            # Receive the username from the client
            username = receive_message(Client_w)
            if username is None:
                # Client disconnected, handle accordingly
                return
            print(f"Received username: {username}")
            # Store the username in the global dictionary
            client_usernames[Client_w] = username
        except:
            print("Failed to receive username from the client")
            return
        send_message(Client_w,str(number_of_players_FG))
        try:
            if not first1:
                no_clients_A_str =receive_message(Client_w)
                no_clients_A = int(no_clients_A_str)
                print(no_clients_A)
                first1 =True
        except:
            print("problem in recieve number of players")
            players_waiting_room_FG =[]
            first1= False
            return()
        print(f"{number_of_players_FG} clients in History Quiz")
        if number_of_players_FG == no_clients_A:
            print("History Quiz start")
            try:
                quiz_thread1 = threading.Thread(target=game_begin, args=('db_history.csv', players_waiting_room_FG,no_clients_A))
                quiz_thread1.start()
                players_waiting_room_FG = []
            except:
                print("problem in try to create thread")
                return()
    elif Ctopic == 'B':
        try:
            players_waiting_room_SG.append(Client_w)
            number_of_players_SG = len(players_waiting_room_SG)
            print("added new player to Technology Quiz")
        except:
            print("error by trying to enter the room")
            return()
        try:
            print(players_waiting_room_SG)
            send_message(Client_w, str(number_of_players_SG))
            print("the number of the client sent")
        except:
            print("there was error by sending the number of the player")
            return()
        try:
            # Receive the username from the client
            username = receive_message(Client_w)
            if username is None:
                # Client disconnected, handle accordingly
                return
            print(f"Received username: {username}")
            # Store the username in the global dictionary
            client_usernames[Client_w] = username
        except:
            print("Failed to receive username from the client")
            return
        send_message(Client_w, str(number_of_players_SG))
        try:
            if not first2:
                no_clients_B_str =receive_message(Client_w)
                no_clients_B = int(no_clients_B_str)
                print(no_clients_B)
                first2 =True
        except:
            print("problem in recieve number of players")
            players_waiting_room_SG =[]
            first2 = False
            return()
        print(f"{number_of_players_SG} clients in Technology")
        if number_of_players_SG == no_clients_B:
            print("technology start")
            try:
                quiz_thread2 = threading.Thread(target=game_begin, args=('db_technology.csv', players_waiting_room_SG,no_clients_B))
                quiz_thread2.start()
                players_waiting_room_SG = []
            except:
                print("problem in try to create thread")
                return ()

# Function to start a quiz game with a given set of questions
def game_begin(path, players_room, num_of_players):
    global first1,first2
    Flag =True
    points_of_the_game = [0] * num_of_players
    scores_of_the_game = {client: 0 for client in players_room}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            question = row[0]
            if question == 'end':
                first1 =False
                first2 =False
            option = row[1]
            correct_ans = str(row[2])
            if not Flag:
                num_of_players -= 1
                Flag =True
            # Send question and options to each player
            for player in range(num_of_players):
                if players_room[player]:
                    try:
                        # Send question
                        send_message(players_room[player], question)
                        # Send options
                        send_message(players_room[player], option)
                        # Print debug information
                        print(f"Question sent to player {player + 1}")
                    except Exception as e:
                        print(f"Problem in sending question to player {player + 1}: {e}")
                        players_room[player] = None
                        Flag = False
                        return

            for player in range(num_of_players):
                if players_room[player]:
                    try:
                        Countdown_received = receive_message(players_room[player])
                        print(str(Countdown_received) + "Countdown_received")
                    except:
                        print("problem in coundown receive")
                        return
                    try:
                        # Receive choice from player
                        choice_received = receive_message(players_room[player])
                        print(f"Player {player + 1} chose: {choice_received}")
                    except Exception as e:
                        print(f"Problem in receiving choice from player {player + 1}: {e}")
                        players_room[player] = None
                        Flag = False
                        #return
                    try:
                        send_message(players_room[player], correct_ans)
                        int_Countdown_received = int(Countdown_received)
                        if correct_ans== 'a':
                            number_of_answer = 0
                        if correct_ans == 'b':
                            number_of_answer = 1
                        if correct_ans == 'c':
                            number_of_answer = 2
                        if correct_ans == 'd':
                            number_of_answer = 3
                        if number_of_answer == int(choice_received):
                            points_of_the_game[player] += int_Countdown_received
                        # Update scores
                        scores_of_the_game[players_room[player]] = points_of_the_game[player]
                    except Exception as e:
                        print(f"Problem in communication with player {player + 1}: {e}")
                        players_room[player] = None
                        Flag = False
                        #return

                sorted_players = sorted(players_room, key=lambda player: scores_of_the_game.get(player, 0), reverse=True)
                formatted_scores = ":".join([f"{sorted_players.index(player) + 1}.{client_usernames.get(player, 'Unknown')}:{scores_of_the_game.get(player, 0)}" for player in sorted_players])

                if player + 1 == num_of_players :
                    for player in range(num_of_players):
                        if players_room[player]:
                            try:
                                send_message(players_room[player],formatted_scores)
                            except:
                                print("there is problem to send the formatted scores")
                                players_room[player] = None
                                Flag = False
            for player in range(num_of_players):
                if players_room[player]:
                    try:
                        update_leaderboard(client_usernames.get(players_room[player], 'Unknown'), scores_of_the_game[players_room[player]])
                    except:
                        print("there is problem to update scores")
                        players_room[player] = None
                        Flag = False

# Load existing data from "winners" database
def load_winners():
    try:
        with open('winners.csv', mode='r') as file:
            reader = csv.reader(file)
            winners = list(reader)
        return winners
    except FileNotFoundError:
        return []

# Save updated data to "winners" database
def save_winners(winners):
    with open('winners.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(winners)

# Update the leaderboard and check for changes
def update_leaderboard(username, scoring_points):
    winners = load_winners()

    # Check if the username is already in the leaderboard
    user_found = False
    for i, (name, score) in enumerate(winners):
        if name == username:
            winners[i] = (name, max(int(score), scoring_points))
            user_found = True
            break

    # If the user is not in the leaderboard, add them
    if not user_found:
        winners.append((username, scoring_points))

    # Sort the leaderboard by score in descending order
    winners.sort(key=lambda x: int(x[1]), reverse=True)

    # Keep only the top 5 leaders
    winners = winners[:5]

    # Save the updated leaderboard
    save_winners(winners)

    return winners


while True:
    ClientIn, addr = s.accept()
    print("Connection has been established to a new client")
    if ClientIn:
        connect_thread = threading.Thread(target=password, args=(ClientIn,))
        connect_thread.start()
    ClientIn = []