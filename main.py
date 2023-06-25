import math
import socket
import os
import time
import binascii
import threading

CONNECTED = False
role = None
DST_IP = None
DST_PORT = None
MAX_COUNTDOWN = 30
countdown = MAX_COUNTDOWN
TIMEOUT = 5


def server_login():
    global role, DST_IP, DST_PORT, CONNECTED
    role = False
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_port = input("Port(20001): ")
    server_socket.bind(("", int(server_port)))
    msg, (DST_IP, DST_PORT) = server_socket.recvfrom(1500)
    crc = int.from_bytes(msg[-2:], 'big')
    print("Init msg: ")
    process_msg(msg)

    while binascii.crc_hqx(msg[:-2], 0) != crc:
        print("Nack sent")
        server_socket.sendto(add_header('', 0, '1'), (DST_IP, DST_PORT))
        msg, (DST_IP, DST_PORT) = server_socket.recvfrom(1500)
        print("Init msg correction: ")
        process_msg(msg)

    print("CLIENT PORT: ", DST_PORT)

    print("Ack sent")
    server_socket.sendto(add_header('', 0, '0'), (DST_IP, DST_PORT))
    server_socket.settimeout(60)
    CONNECTED = True

    return server_socket


def client_login():
    global role, DST_IP, DST_PORT, CONNECTED, TIMEOUT
    role = True
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst_ip = input("Server ip (192.168.56.1): ")
    dst_port = int(input("Server port (20001): "))
    DST_IP = dst_ip
    DST_PORT = dst_port
    client_socket.sendto(add_header('', 0, '5'), (DST_IP, DST_PORT))
    print("Connection init packet: ")
    process_msg(add_header('', 0, '5'))

    err_count = 0
    while True:
        try:
            client_socket.settimeout(TIMEOUT)
            print("Ack:")
            ack = client_socket.recvfrom(1500)
            process_msg(ack[0])
            flag = True
            if chr(ack[0][0]) != '0':
                print("Damaged connection packet")
                print("Resending connection packet")
                client_socket.sendto(add_header('', 0, '5'), (DST_IP, DST_PORT))
                flag = False
        except (socket.timeout, ConnectionResetError) as e:
            if err_count >= 3:
                print("sth is wrong, ending connection")
                CONNECTED = False
                client_socket.close()
                quit()
            err_count += 1
            print("Timeout triggered")
            print("Resending connection packet")
            client_socket.sendto(add_header('', 0, '5'), (DST_IP, DST_PORT))
            flag = False
        if flag:
            break

    CONNECTED = True

    client_socket.settimeout(60)
    keepalive_thread = threading.Thread(target=keepalive, args=(client_socket,))
    keepalive_thread.start()

    return client_socket


def add_header(msg, fragment_id, msg_type, flag=False):
    if isinstance(msg, str):
        msg = msg.encode()
    msg_len = (len(msg) + 7).to_bytes(2, byteorder='big')
    fragment_id = fragment_id.to_bytes(2, byteorder='big')
    msg = msg_type.encode() + msg_len + fragment_id + msg
    crc = binascii.crc_hqx(msg, 0)
    if flag:
        if crc > 0:
            crc -= 1
        else:
            crc += 1
    crc = crc.to_bytes(2, 'big')
    return msg + crc


def switch_roles(current_socket):
    global role, CONNECTED

    print("Sending switch roles signal")
    current_socket.sendto(add_header('', 0, '7'), (DST_IP, DST_PORT))
    process_msg(add_header('', 0, '7'))

    err_count = 0
    while True:
        try:
            current_socket.settimeout(TIMEOUT)
            ack = current_socket.recvfrom(1500)
            print("Ack:")
            process_msg(ack[0])
            flag = True
            if chr(ack[0][0]) != '0':
                print("Damaged switch-roles packet")
                print("Resending switch-roles packet")
                current_socket.sendto(add_header('', 0, '7'), (DST_IP, DST_PORT))
                process_msg(add_header('', 0, '7'))
                flag = False
        except (socket.timeout, ConnectionResetError) as e:
            if err_count >= 3:
                print("sth is wrong, ending connection")
                CONNECTED = False
                current_socket.close()
                quit()
            err_count += 1
            print("Timeout triggered")
            print("Resending switch-roles packet")
            current_socket.sendto(add_header('', 0, '7'), (DST_IP, DST_PORT))
            process_msg(add_header('', 0, '7'))
            flag = False
        if flag:
            break

    role = False


def keepalive(client_socket):
    global countdown, CONNECTED
    print("Keepalive started")
    while role and CONNECTED:
        if countdown < 0:
            # print("Keepalive sent")
            client_socket.sendto(add_header('', 0, '2'), (DST_IP, DST_PORT))
            countdown = MAX_COUNTDOWN
            err_count = 0
            while True:
                try:
                    client_socket.settimeout(TIMEOUT)
                    client_socket.recvfrom(1500)
                    flag = True
                except (socket.timeout, ConnectionResetError) as e:
                    print("Keepalive not delivered, maybe not acknowledged")
                    if err_count >= 3:
                        print("sth is wrong, ending connection")
                        CONNECTED = False
                        break
                    err_count += 1
                    client_socket.sendto(add_header('', 0, '2'), (DST_IP, DST_PORT))
                    flag = False
                if flag:
                    client_socket.settimeout(60)
                    break
        countdown -= 1
        time.sleep(1)
    print("Keepalive ended")


def end_connection(current_socket):
    global CONNECTED

    current_socket.sendto(add_header('', 0, '6'), (DST_IP, DST_PORT))
    print("Sending end-connection packet:")
    process_msg(add_header('', 0, '6'))

    err_count = 0
    while True:
        try:
            current_socket.settimeout(TIMEOUT)
            ack = current_socket.recvfrom(1500)
            print("Ack: ")
            process_msg(ack[0])
            flag = True
            if chr(ack[0][0]) != '0':
                print("Damaged end-connection packet")
                print("Resending end-connection packet")
                current_socket.sendto(add_header('', 0, '6'), (DST_IP, DST_PORT))
                process_msg(add_header('', 0, '6'))
                flag = False
        except (socket.timeout, ConnectionResetError) as e:
            if err_count >= 3:
                CONNECTED = False
                print("sth is wrong, ending connection")
                current_socket.close()
                quit()
            err_count += 1
            print("Timeout triggered")
            print("Resending end-connection packet")
            current_socket.sendto(add_header('', 0, '6'), (DST_IP, DST_PORT))
            process_msg(add_header('', 0, '6'))
            flag = False
        if flag:
            break

    current_socket.close()
    CONNECTED = False


def send_msg(current_socket):
    global countdown, CONNECTED

    file_or_msg = input("Text message(0) or file(1)?")
    destination_ip = input(f"Destination IP ({DST_IP}):")
    destination_port = int(input(f"Destination port ({DST_PORT}): "))
    fragment_size = int(input("Max fragment size (9-1465): "))
    mistakes = int(input("Number of damaged packets: "))

    addr = (destination_ip, destination_port)

    if file_or_msg == '0':
        msg_content = input("Message: ")
        number_of_packets = math.ceil(len(msg_content.encode()) / (fragment_size - 7))

        init_packet = add_header(
            number_of_packets.to_bytes(2, byteorder='big') + fragment_size.to_bytes(2, byteorder='big'), 0, '3')
        current_socket.sendto(init_packet, addr)
        countdown = MAX_COUNTDOWN
        print("Sending init packet")
        process_msg(init_packet)

        err_count = 0
        while True:
            try:
                current_socket.settimeout(TIMEOUT)
                ack = current_socket.recvfrom(1500)
                print("Ack: ")
                process_msg(ack[0])
                countdown = MAX_COUNTDOWN
                flag = True
                if chr(ack[0][0]) != '0':
                    flag = False
                    print("Resending init packet")
                    init_packet = add_header(
                        number_of_packets.to_bytes(2, byteorder='big') + fragment_size.to_bytes(2, byteorder='big'), 0,
                        '3')
                    current_socket.sendto(init_packet, addr)
                    process_msg(init_packet)
                    countdown = MAX_COUNTDOWN
            except (socket.timeout, ConnectionResetError) as e:
                if err_count >= 3:
                    CONNECTED = False
                    print("sth is wrong, ending connection")
                    current_socket.close()
                    quit()
                err_count += 1
                print("Timeout triggered!")
                print("Resending init packet")
                init_packet = add_header(
                    number_of_packets.to_bytes(2, byteorder='big') + fragment_size.to_bytes(2, byteorder='big'), 0, '3')
                current_socket.sendto(init_packet, addr)
                process_msg(init_packet)
                countdown = MAX_COUNTDOWN
                flag = False
            if flag:
                break

        for i in range(number_of_packets):
            frag_content = msg_content[0:fragment_size - 7]
            msg_content = msg_content[fragment_size - 7:]

            if mistakes > 0:
                mistakes -= 1
                msg = add_header(frag_content, i, '4', True)
            else:
                msg = add_header(frag_content, i, '4')

            current_socket.sendto(msg, addr)
            print("Sending: ", i)
            process_msg(msg)
            countdown = MAX_COUNTDOWN

            err_count = 0
            while True:
                try:
                    current_socket.settimeout(TIMEOUT)
                    ack = current_socket.recvfrom(1500)
                    countdown = MAX_COUNTDOWN
                    flag = True
                    if chr(ack[0][0]) != '0':
                        print('Nack received')
                        msg = add_header(frag_content, i, '4')
                        current_socket.sendto(msg, addr)
                        print("Resending: ", i)
                        process_msg(msg)
                        countdown = MAX_COUNTDOWN
                        flag = False
                except (socket.timeout, ConnectionResetError) as e:
                    if err_count >= 3:
                        CONNECTED = False
                        print("sth is wrong, ending connection")
                        current_socket.close()
                        quit()
                    err_count += 1
                    print("Timeout triggered!")
                    current_socket.sendto(msg, addr)
                    print("Sending: ", i)
                    process_msg(msg)
                    countdown = MAX_COUNTDOWN
                    flag = False
                if flag:
                    break

    elif file_or_msg == '1':
        file_name = input("File name: ")
        file_size = os.path.getsize(file_name)

        number_of_packets = math.ceil(file_size / (fragment_size - 7))

        init_msg_content = number_of_packets.to_bytes(2, byteorder='big') + fragment_size.to_bytes(2,
                                                                                                   byteorder='big') + file_name.encode()

        current_socket.sendto(add_header(init_msg_content, 0, '8'), addr)
        countdown = MAX_COUNTDOWN
        print("Sending init packet: ")
        process_msg(init_msg_content)

        err_count = 0
        while True:
            print("Resending init packet")
            try:
                current_socket.settimeout(TIMEOUT)
                ack = current_socket.recvfrom(1500)
                countdown = MAX_COUNTDOWN
                flag = True
                if chr(ack[0][0]) != '0':
                    print("Nack received")
                    flag = False
                    current_socket.sendto(add_header(init_msg_content, 0, '8'), addr)
                    print("Resending init packet: ")
                    process_msg(init_msg_content)
                    countdown = MAX_COUNTDOWN
            except (socket.timeout, ConnectionResetError) as e:
                if err_count >= 3:
                    CONNECTED = False
                    print("sth is wrong, ending connection")
                    current_socket.close()
                    quit()
                err_count += 1
                print("Timeout triggered!")
                current_socket.sendto(add_header(init_msg_content, 0, '8'), addr)
                print("Resending init packet: ")
                process_msg(init_msg_content)
                countdown = MAX_COUNTDOWN
                flag = False
            if flag:
                break

        countdown = MAX_COUNTDOWN

        with open(file_name, "rb") as f:

            for i in range(number_of_packets):
                frag_content = f.read(fragment_size - 7)

                if mistakes > 0:
                    mistakes -= 1
                    msg = add_header(frag_content, i, '4', True)
                else:
                    msg = add_header(frag_content, i, '4')

                current_socket.sendto(msg, addr)
                print("Sending: ", i)
                process_msg(msg)
                countdown = MAX_COUNTDOWN

                err_count = 0
                while True:
                    try:
                        current_socket.settimeout(TIMEOUT)
                        ack = current_socket.recvfrom(1500)
                        countdown = MAX_COUNTDOWN
                        flag = True
                        if chr(ack[0][0]) != '0':
                            print("Nack received")
                            flag = False
                            msg = add_header(frag_content, i, '4')
                            current_socket.sendto(msg, addr)
                            print("Resending: ", i)
                            process_msg(msg)
                            countdown = MAX_COUNTDOWN
                    except (socket.timeout, ConnectionResetError) as e:
                        if err_count >= 3:
                            CONNECTED = False
                            print("sth is wrong, ending connection")
                            current_socket.close()
                            quit()
                        err_count += 1
                        print("Timeout triggered!")
                        msg = add_header(frag_content, i, '4')
                        current_socket.sendto(msg, addr)
                        print("Resending: ", i)
                        process_msg(msg)
                        countdown = MAX_COUNTDOWN
                        flag = False
                    if flag:
                        break

                countdown = MAX_COUNTDOWN

        print(
            f"\nFile name: {os.path.basename(file_name)}\nPath to the received file: {os.path.abspath(file_name)}\n"
            f"Number of fragments: {number_of_packets}\nFragment size: {fragment_size} B\nFile size: {file_size} B\n")

    current_socket.settimeout(60)


def receive_msg(current_socket):
    global role, CONNECTED, countdown
    current_socket.settimeout(60)
    init_msg = current_socket.recvfrom(1500)
    countdown = MAX_COUNTDOWN

    err_count = 0
    if not crc_check(init_msg[0]):
        print("Damaged init packet received!")
        current_socket.sendto(add_header('', 0, '1'), (DST_IP, DST_PORT))
        countdown = MAX_COUNTDOWN
        while True:
            try:
                init_msg = current_socket.recvfrom(1500)
                countdown = MAX_COUNTDOWN
                if crc_check(init_msg[0]):
                    current_socket.sendto(add_header('', 0, '0'), (DST_IP, DST_PORT))
                    countdown = MAX_COUNTDOWN
                    flag = True
                else:
                    print("Damaged packet received!")
                    flag = False
                    current_socket.sendto(add_header('', 0, '1'), (DST_IP, DST_PORT))
                    countdown = MAX_COUNTDOWN
            except (socket.timeout, ConnectionResetError) as e:
                if err_count >= 3:
                    print("sth is wrong, ending connection")
                    current_socket.close()
                    quit()
                err_count += 1
                print("Packet not received!")
                current_socket.sendto(add_header('', 0, '1'), (DST_IP, DST_PORT))
                countdown = MAX_COUNTDOWN
                flag = False
            if flag:
                break
    else:
        print("Ack sent")
        current_socket.sendto(add_header('', 0, '0'), (DST_IP, DST_PORT))
        countdown = MAX_COUNTDOWN

    msg_type = chr(init_msg[0][0])

    if msg_type == '0':
        print("Ack received")
        return
    elif msg_type == '1':
        print("Nack received")
        return
    elif msg_type == '2':
        print("Keepalive received")
        return
    elif msg_type == '3':
        print("Init packet received")
        process_msg(init_msg[0])
        number_of_incoming_packets = int.from_bytes(init_msg[0][5:7], 'big')
        fragment_size = int.from_bytes(init_msg[0][7:9], 'big')
        countdown = MAX_COUNTDOWN
    elif msg_type == '6':
        print("Connection end")
        current_socket.close()
        CONNECTED = False
        return
    elif msg_type == '7':
        print("Switch roles")
        role = True
        keepalive_thread = threading.Thread(target=keepalive, args=(current_socket,))
        keepalive_thread.start()
        return
    elif msg_type == '8':
        print("Init packet received (files)")
        process_msg(init_msg[0])
        init_msg_content = init_msg[0][5:-2]
        number_of_incoming_packets = int.from_bytes(init_msg_content[0:2], 'big')
        fragment_size = int.from_bytes(init_msg_content[2:4], 'big')
        file_name = init_msg_content[4:].decode()
        countdown = MAX_COUNTDOWN
    elif msg_type == '4':
        print("Sth wrong")
        return
    elif msg_type == '5':
        print("Sth wrong")
        return

    print("Incoming packets: ", number_of_incoming_packets)
    full_message = [None] * number_of_incoming_packets

    for i in range(number_of_incoming_packets):

        # if i == 3:
        #   msg = current_socket.recvfrom(1500)
        # print("ignored: ")
        # process_msg(msg[0])

        connection_err = 0
        while True:
            try:
                current_socket.settimeout(TIMEOUT)
                msg = current_socket.recvfrom(1500)
                if chr(msg[0][0]) != '4':
                    break
                countdown = MAX_COUNTDOWN
                process_msg(msg[0])
                flag = True
                if not crc_check(msg[0]):
                    flag = False
                    print("Damaged packet received")
                    print("Nack sent")
                    current_socket.sendto(add_header('', i, '1'), (DST_IP, DST_PORT))
            except (socket.timeout, ConnectionResetError) as e:
                if connection_err == 3:
                    CONNECTED = False
                    current_socket.close()
                    quit()
                connection_err += 1
                current_socket.sendto(add_header('', i, '1'), (DST_IP, DST_PORT))
                countdown = MAX_COUNTDOWN
                print("Timeout triggered!")
                flag = False
            if flag:
                break

        if chr(msg[0][0]) != '4':
            i -= 1
            continue

        print("Ack sent")
        current_socket.sendto(add_header('', i, '0'), (DST_IP, DST_PORT))
        countdown = MAX_COUNTDOWN

        if msg_type == '3':
            full_message[i] = msg[0][5:-2].decode()
        if msg_type == '8':
            full_message[i] = msg[0][5:-2]

    if msg_type == '3':
        full_message = ''.join(full_message)
        print("Number of packets to form the message: ", number_of_incoming_packets)
        print("Fragment size: ", fragment_size)
        print("Full message: ", full_message)

    elif msg_type == '8':
        print("For testing: C:\\Users\\matej\\PycharmProject")
        file_path = input("Where to save the file? (leave blank for cwd): ")
        if file_path == '':
            file_path = os.path.basename(file_name)
        else:
            file_path = file_path + "\\" + os.path.basename(file_name)

        if len(full_message) > 0:
            file_content = full_message[0]
        else:
            file_content = ''.encode()

        for i in range(1, len(full_message)):
            file_content += full_message[i]

        with open(file_path, "wb") as f:
            f.write(file_content)

        print(f"File name: {file_path}\nPath to the received file: {os.path.abspath(file_path)}\nNumber of fragments: "
              f"{number_of_incoming_packets}\nFragment size: {fragment_size} B\nFile size: {os.path.getsize(file_name)} B\n")

    current_socket.settimeout(60)


def process_msg(msg):
    msg_type = chr(msg[0])
    msg_len = int.from_bytes(msg[1:3], 'big')
    msg_frag = int.from_bytes(msg[3:5], 'big')

    msg_data = msg[5:-2]

    crc = int.from_bytes(msg[-2:], 'big')

    print("Msg type: ", msg_type)
    print("Msg len: ", msg_len)
    print("Msg frag number: ", msg_frag)
    print("Data: ", msg_data)
    print("Crc: ", crc, '\n')


def crc_check(msg):
    crc_received = int.from_bytes(msg[-2:], 'big')
    crc_calculated = binascii.crc_hqx(msg[:-2], 0)
    print("crc_received: ", crc_received, "crc_calculated: ", crc_calculated)
    if crc_calculated == crc_received:
        return True
    else:
        return False


def main():
    login = input("Login as server - 0, login as client - 1: ")
    if login == '0':
        current_socket = server_login()
    elif login == '1':
        current_socket = client_login()

    while True:
        if role:
            user_input = input("Send message - 0, switch roles - 1, exit - 2: ")
            if user_input == '0':
                send_msg(current_socket)
            elif user_input == '1':
                switch_roles(current_socket)
            elif user_input == '2':
                end_connection(current_socket)
                break
        else:
            print("receive called")
            receive_msg(current_socket)

        if not CONNECTED:
            break


if __name__ == '__main__':
    main()
