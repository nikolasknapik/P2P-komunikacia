import socket
import struct
import threading
import os
import time
import queue

def create_header(message_type, message_id, fragment_number, total_fragments, crc):
    # Vytvorenie hlavičky správy pomocou štruktúry
    header = struct.pack('!B H H H H', message_type, message_id, fragment_number, total_fragments, crc)
    return header

def calculate_crc(data):
    # Manuálny výpočet CRC-16-CCITT
    crc = 0xFFFF  # Počiatočná hodnota CRC registra
    for byte in data:
        crc ^= byte << 8  # XOR s vyšším bajtom CRC registra
        for _ in range(8):
            if crc & 0x8000:  # Ak je najvyšší bit nastavený
                crc = (crc << 1) ^ 0x1021  # Posun doľava a XOR s polynómom
            else:
                crc <<= 1  # Posun doľava bez XOR
            crc &= 0xFFFF  # Uistiť sa, že CRC zostáva 16-bitové
    return crc


def send_ack(sock, address, message_id, fragment_number, total_fragments):
    # Odoslanie ACK správy s úplnou hlavičkou
    ack_message = b'ACK'
    crc = calculate_crc(ack_message)
    header = create_header(ACK_DATA, message_id, fragment_number, total_fragments, crc)
    packet = header + ack_message
    sock.sendto(packet, address)

def send_nack(sock, address, message_id, fragment_number, total_fragments):
    # Odoslanie NACK správy s úplnou hlavičkou
    nack_message = b'NACK'
    crc = calculate_crc(nack_message)
    header = create_header(NACK_DATA, message_id, fragment_number, total_fragments, crc)
    packet = header + nack_message
    sock.sendto(packet, address)

def send_message(sock, address, message, fragment_size, filename=None):
    # Funkcia na odoslanie správy rozdelenej na fragmenty
    message_id = int(time.time()) % 65535
    total_fragments = (len(message) + fragment_size - 1) // fragment_size

    # Ak posielame súbor, najprv pošleme FILE_INFO správu
    if filename:
        filename_bytes = filename.encode()
        crc = calculate_crc(filename_bytes)
        header = create_header(FILE_INFO, message_id, 0, 0, crc)
        packet = header + filename_bytes

        # Odoslanie FILE_INFO a čakanie na ACK
        while True:
            sock.sendto(packet, address)
            print(f"Odoslaný FILE_INFO s názvom súboru: {filename}")
            try:
                ack_info = ack_queue.get(timeout=1)
                if ack_info['address'] != address:
                    continue  # Ignorovať ACK/NACK z iných adries
                if ack_info['message_id'] != message_id:
                    continue  # Ignorovať ACK/NACK pre iné správy

                if ack_info['ack_type'] == ACK_DATA:
                    print("ACK prijaté pre FILE_INFO")
                    break
                elif ack_info['ack_type'] == NACK_DATA:
                    print("NACK prijaté pre FILE_INFO, opätovné odoslanie")
            except queue.Empty:
                print("Nedostal ACK/NACK pre FILE_INFO, opätovné odoslanie")

    display_sending_info(message, filename, fragment_size)

    # Pokračujeme v odosielaní dátových fragmentov
    for fragment_number in range(total_fragments):
        fragment_start = fragment_number * fragment_size
        fragment_data = message[fragment_start:fragment_start + fragment_size]

        crc = calculate_crc(fragment_data)
        header = create_header(DATA, message_id, fragment_number, total_fragments, crc)

        if fragment_number == 2:
            # Simulácia poškodenia dát na treťom fragmente
            print("Simulácia poškodenia dát na fragmente 3")
            crc = 5
            header = create_header(DATA, message_id, fragment_number, total_fragments, crc)

        packet = header + fragment_data

        while True:
            sock.sendto(packet, address)
            print(f"Odoslaný fragment {fragment_number + 1}/{total_fragments}")
            try:
                # Čakanie na ACK/NACK z fronty s timeoutom
                ack_info = ack_queue.get(timeout=1)


                if ack_info['message_id'] != message_id or ack_info['fragment_number'] != fragment_number:
                    continue  # Ignorovať ACK/NACK pre iné správy alebo fragmenty

                if ack_info['ack_type'] == ACK_DATA:
                    print(f"ACK prijaté pre fragment {fragment_number + 1}")
                    break
                elif ack_info['ack_type'] == NACK_DATA:
                    print(f"NACK prijaté pre fragment {fragment_number + 1}, opätovné odoslanie")
                    crc = calculate_crc(fragment_data)
                    header = create_header(DATA, message_id, fragment_number, total_fragments, crc)
                    packet = header + fragment_data

            except queue.Empty:
                print(f"Nedostal ACK/NACK pre fragment {fragment_number + 1}, opätovné odoslanie")

    print("Prenos správy dokončený")

def sending_loop(sock, address):
    global fragment_size
    while True:
        if not handshake_complete.is_set():
            initiate_handshake(sock, address)
            print("Handshake iniciovaný. Čakám na dokončenie")
            handshake_complete.wait()
            print("Handshake dokončený. Spojenie nadviazané")

        fragment_size = get_fragment_size()

        message, filename = get_message_to_send()
        if message:
            send_message(sock, address, message, fragment_size, filename)

def initiate_handshake(sock, address):
    if handshake_complete.is_set():
        return
    init_message = "SYN".encode()
    header = create_header(SYN, 0, 0, 0, calculate_crc(init_message))
    packet = header + init_message
    sock.sendto(packet, address)
    print("SYN odoslaný")

def receive_message(sock, packet, address):
    global missed_heartbeats
    if len(packet) >= 9:
        # Spracovanie správ s úplnou hlavičkou
        header = packet[:9]
        data = packet[9:]
        message_type, message_id, fragment_number, total_fragments, received_crc = struct.unpack('!B H H H H', header)
        calculated_crc = calculate_crc(data)
    else:
        # Spracovanie kratších správ
        message_type = struct.unpack('!B', packet[:1])[0]
        data = packet[1:]
        message_id = fragment_number = total_fragments = received_crc = None
        calculated_crc = None

    # Resetovanie počítadla zmeškaných heartbeatov pri prijatí akejkoľvek správy
    missed_heartbeats = 0

    if message_type == SYN:
        print("Prijatý SYN. Odosielam SYN_ACK")
        response = "SYN_ACK".encode()
        response_header = create_header(SYN_ACK, 0, 0, 0, calculate_crc(response))
        sock.sendto(response_header + response, address)
        # Ak sme ešte neiniciovali handshake, iniciujeme ho teraz
        if not handshake_complete.is_set():
            initiate_handshake(sock, address)

    elif message_type == SYN_ACK:
        print("Prijatý SYN_ACK. Odosielam ACK.")
        ack = "ACK".encode()
        ack_header = create_header(ACK, 0, 0, 0, calculate_crc(ack))
        sock.sendto(ack_header + ack, address)
        # Nastavíme handshake_complete
        handshake_complete.set()

    elif message_type == ACK:
        print("Prijatý ACK. Handshake dokončený.")
        handshake_complete.set()

    elif message_type == FILE_INFO:
        filename = data.decode()
        print(f"Prijatý FILE_INFO s názvom súboru: {filename}")
        # Odoslať ACK pre FILE_INFO
        send_ack(sock, address, message_id, 0, 0)
        # Uložiť názov súboru do message_metadata
        if address not in message_metadata:
            message_metadata[address] = {}
        message_metadata[address]['filename'] = filename

    elif message_type == DATA:
        if calculated_crc == received_crc:
            send_ack(sock, address, message_id, fragment_number, total_fragments)
            success = True
        else:
            send_nack(sock, address, message_id, fragment_number, total_fragments)
            success = False

        display_receiving_info(fragment_number, total_fragments, success)

        if address not in message_fragments:
            message_fragments[address] = {}
            message_total_fragments[address] = total_fragments
            if address not in message_metadata:
                message_metadata[address] = {}
            message_metadata[address]['start_time'] = time.time()
            if 'filename' not in message_metadata[address]:
                message_metadata[address]['filename'] = None

        # Kontrola duplicitných fragmentov
        if fragment_number in message_fragments[address]:
            return  # Fragment už bol prijatý

        message_fragments[address][fragment_number] = data

        if len(message_fragments[address]) == total_fragments:
            end_time = time.time()
            total_size = sum(len(frag) for frag in message_fragments[address].values())
            message = b''.join(message_fragments[address][i] for i in sorted(message_fragments[address]))
            filename = message_metadata[address]['filename']

            if filename:
                save_file_path = os.path.join(save_path, filename)
                with open(save_file_path, 'wb') as f:
                    f.write(message)
                print(f"Súbor uložený na {os.path.abspath(save_file_path)}")
            else:
                print(f"Prijatá správa: {message.decode()}")

            display_final_receiving_info(filename, total_size, save_path, message_metadata[address]['start_time'], end_time)

            del message_fragments[address]
            del message_total_fragments[address]
            del message_metadata[address]

    elif message_type == ACK_DATA or message_type == NACK_DATA:
        # Vloženie ACK/NACK správy do fronty
        ack_queue.put({
            'ack_type': message_type,
            'message_id': message_id,
            'fragment_number': fragment_number,
            'address': address
        })

    elif message_type == HEARTBEAT:
        # Odpoveď na heartbeat
        heartbeat_response = "HEARTBEAT_ACK".encode()
        header = create_header(HEARTBEAT_ACK, 0, 0, 0, calculate_crc(heartbeat_response))
        sock.sendto(header + heartbeat_response, address)


    elif message_type == HEARTBEAT_ACK:
        missed_heartbeats = 0


    else:
        print("Prijatý neznámy typ správy")


def receiving_loop(sock):
    global connection_active
    while connection_active.is_set():
        try:
            packet, address = sock.recvfrom(65536)
            receive_message(sock, packet, address)
        except ConnectionResetError:
            print("Spojenie prerusene partnerom")
            continue
        except socket.timeout:
            continue

def heartbeat_loop(sock, address):
    global missed_heartbeats
    while connection_active.is_set():
        time.sleep(5)
        heartbeat_message = "HEARTBEAT".encode()
        header = create_header(HEARTBEAT, 0, 0, 0, calculate_crc(heartbeat_message))
        sock.sendto(header + heartbeat_message, address)
        missed_heartbeats += 1

        if missed_heartbeats >= 3:
            print("Spojenie bolo stratené kvôli zmeškaným heartbeatom.")
            connection_active.clear()
            break

def get_addresses():
    local_port = int(input("Zadajte lokálny port pre počúvanie: "))
    remote_port = int(input("Zadajte vzdialený port pre odosielanie: "))
    remote_ip = input("Zadaj vzdialenu adressu: ")  # ívame localhost pre testovanie

    local_address = ('' ,local_port)
    remote_address = (remote_ip, remote_port)

    return local_address, remote_address

def get_save_path():
    save_path = input("Zadajte cestu na sťahovanie: ")
    if os.path.isdir(save_path):
        return save_path
    else:
        print("Adresár neexistuje. Skúste to znova")
        return get_save_path()
    
def get_fragment_size():
    while True:
        fragment_size = int(input("Zadajte maximálnu veľkosť fragmentov (1 - 1460): "))
        if 1 <= fragment_size <= MAX_MTU:
            return fragment_size
        else:
            print("Zadajte platnú veľkosť fragmentu")

def get_message_to_send():
    choice = input("1 pre správu. 2 pre súbor: ")
    if choice == '1':
        message = input("Zadajte správu na odoslanie: ").encode()
        filename = None
    elif choice == '2':
        file_path = input("Zadajte cestu k súboru na odoslanie: ")
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                message = f.read()
            filename = os.path.basename(file_path)
        else:
            print("Súbor neexistuje")
            return get_message_to_send()
    else:
        print("Neplatná voľba")
        return get_message_to_send()
    return message, filename

def display_sending_info(message, filename, fragment_size):
    total_size = len(message)
    total_fragments = (total_size + fragment_size - 1) // fragment_size
    print(f"Začiatok prenosu...")
    if filename:
        print(f"Odosielam súbor: {filename}")
    else:
        print("Odosielam textovú správu")
    print(f"Celková veľkosť: {total_size} bajtov")
    print(f"Veľkosť fragmentu: {fragment_size} bajtov")
    print(f"Celkový počet fragmentov na odoslanie: {total_fragments}")
    if total_size % fragment_size != 0:
        last_fragment_size = total_size % fragment_size
        print(f"Veľkosť posledného fragmentu: {last_fragment_size} bajtov")

def display_receiving_info(fragment_number, total_fragments, success):
    status = "úspešne" if success else "s chybami"
    print(f"Prijatý fragment {fragment_number + 1}/{total_fragments} {status}")

def display_final_receiving_info(filename, total_size, save_path, start_time, end_time):
    duration = end_time - start_time
    print(f"Prijatá kompletná správa/súbor.")
    if filename:
        print(f"Súbor uložený v: {os.path.abspath(os.path.join(save_path, filename))}")
    else:
        print("Prijatá textová správa.")
    print(f"Celková veľkosť: {total_size} bajtov")
    print(f"Dĺžka prenosu: {duration:.2f} sekúnd")

def start_node():
    global expected_remote_address
    local_address, remote_address = get_addresses()
    expected_remote_address = remote_address
    global save_path
    save_path = get_save_path()

    # Použitie rovnakého socketu pre odosielanie a prijímanie
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(local_address)
    sock.settimeout(1)

    # Spustenie prijímacieho vlákna
    receiving_thread = threading.Thread(target=receiving_loop, args=(sock,))
    receiving_thread.daemon = True
    receiving_thread.start()

    # Spustenie heartbeat vlákna
    heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(sock, remote_address))
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

    # Spustenie odosielacieho cyklu
    sending_loop(sock, remote_address)

# Definície konštánt pre typy správ
SYN = 1
SYN_ACK = 2
ACK = 3
DATA = 4
ACK_DATA = 5
NACK_DATA = 6
HEARTBEAT = 7
HEARTBEAT_ACK = 8
FILE_INFO = 9  

MAX_MTU = 1460

# Globálne udalosti a premenné
handshake_complete = threading.Event()
connection_active = threading.Event()
connection_active.set()
missed_heartbeats = 0

message_fragments = {}
message_total_fragments = {}
message_metadata = {}
save_path = ""
expected_remote_address = None

# Fronta na komunikáciu ACK/NACK medzi vláknami
ack_queue = queue.Queue()

start_node()