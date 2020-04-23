# Simulation of Apple's Bluetooth Find My system.
# April 23, 2020
# Authors: Hannah Huang and Warren Partridge

from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from fastecdsa import keys, curve  # Used for generating EC P-224 keypairs.
import random
import binascii
from binascii import hexlify, unhexlify
import hashlib

iCloudRecords = {}
for i in range(100):
    iCloudRecords[i] = "IRRELEVANT RECORD"
iCloudKeypair = ("nothing", "nothing")
iCloudSecret = b"nothing"


def generate_iCloud_keypair():
    """
    When Bob sets up Find My for the first time and checks the
    "enable offline discovery" box, Find My generates an EC P-224
    private encryption key pair.

    Returns:
      Tuple of (privateKey, publicKey)
    """
    # Generate a private key using the P-224 curve.
    privateKey = keys.gen_private_key(curve.P224)

    # Generate the public key corresponding to the private key we just generated.
    publicKey = keys.get_public_key(privateKey, curve.P224)

    return (privateKey, publicKey)


def do_KDF(SK, message):
    """
    Perform a KDF step using HMAC-SHA-256.
    """

    return HMAC.new(SK, message, SHA256).hexdigest()


def get_SK_i(SK, counter):
    """
    function that generates a current symmetric key SK_i with a
    recursive algorithm: SK_i = KDF(SK_i-1, “update” ).

    argument:
    SK_0: initialized 256 bit secret Sk0, with counter initialized to zero
    func_KDF:
    """

    if counter == 0:
        return SK

    SK_new = unhexlify(do_KDF(SK, b'update'))
    return get_SK_i(SK_new, counter - 1)


# SK_i = key_setup(SK_0, counter)
def compute_u_and_v(SK_i):
    """
    Given the SK_i, two integers u_i and v_i are computed
    using key derivation function (KDF): (u_i,v_i) = KDF(SK_i, “diversify”).
    """

    result = unhexlify(do_KDF(SK_i, b"diversify"))
    result = int.from_bytes(result, byteorder="big")
    result = str(result)[:16]
    u_i = int(result[:len(result) // 2])  # what is "diversify???"
    v_i = int(result[len(result) // 2:])

    return (u_i, v_i)


def generate_new_keypair(currentSK, d, P):
    """
    The new short lived key pair {di, Pi} is generated with the following
    formula: di = ui * d + vi(modulo the order of the P-224 curve),
    and Pi = ui*P + vi*G.
    """

    (u_i, v_i) = compute_u_and_v(currentSK)
    d = iCloudKeypair[0]
    P = iCloudKeypair[1]
    d_bytes = bytes(d.encode())
    P_bytes = bytes(P.encode())
    d_i = u_i * int.from_bytes(d_bytes, byteorder="big") + v_i % (2**2)
    P_i = u_i * int.from_bytes(P_bytes, byteorder="big") + v_i * 2  # Constant G = 2
    return (d_i, P_i)


def encrypt_location_with_publickey(finder_location, P_i):
    """
    After Bob’s device sends PI , surrounding devices receive the key Pi and encrypt their location to Pi with ECIES.
    """

    finder_location = pad(finder_location.encode(), 16)

    P_i_bytes = "{:016x}".format(P_i).encode()[:16]

    temp = AES.new(P_i_bytes, AES.MODE_ECB)
    ct = temp.encrypt(finder_location)

    return hexlify(ct)


def SHA256_hash_to_index(P_i):
    """
    Finder device’s encryption hashes the public key Pi using SHA-256 into lookup index: indexi = SHA256((Pi))
    """

    return hashlib.sha256(str(P_i).encode()).hexdigest()


def perform_query(index_set):
    """
    Bob’s Macbook can send queries to the server using the set of lookup index values that he obtained by
    performing SHA-256 hashing the Pi . The server returns Bob’s Macbook a decent set of records
    representing encrypted locations, Record = {indexi, ECIES(Pi, location) }
    """

    result = []
    for tup in index_set:
        index = tup[0]
        if (iCloudRecords.get(index) != "IRRELEVANT RECORD" and iCloudRecords.get(index) != None):
            result.append((iCloudRecords.get(index), tup[1]))  # Append record and the key we can use to decrypt it.
    return result


def bobs_macbook_tries_to_locate_phone():
    """
    Simulates Bob connecting to iCloud on his Macbook to find his lost phone.

    records = {index_i, (ECIES(p, location)}
    For each record, Find My can decrypt the encrypted locations using d_i , which is the private key
    that can be checked if it matches: (locationi,j, timei,j) = ECIES Decrypt (dj, recordi,j).

    The decryption using the private key hence allows Bob to identify the approximate location of his lost device.

    Returns:
        (str) The found location of Bob's phone.
    """

    d = iCloudKeypair[0]
    P = iCloudKeypair[1]
    SKCounter = 1
    index_set = set()  # (index, d_i)

    for i in range(100):
        currentSK = get_SK_i(iCloudSecret, SKCounter)  # Got SK_i
        d_i, P_i = generate_new_keypair(currentSK, d, P)  # Got d_i, P_i

        index = SHA256_hash_to_index(P_i)
        index_set.add((index, P_i))  # In actuality, this would be d_i. We are substituding AES so we need pub key.
        SKCounter += 1
    returned_records_from_query = perform_query(index_set)

    for tup in returned_records_from_query:
        record, P_i = tup
        P_i_bytes = "{:016x}".format(P_i).encode()[:16]
        cipher = AES.new(P_i_bytes, AES.MODE_ECB)
        locationOfPhone = cipher.decrypt(unhexlify(record))

        print("Bob's Macbook successfully decrypted a location!")
        return unpad(locationOfPhone, 16).decode()

    print("Bob's Macbook couldn't find any location information on iCloud.")
    return None


def share_keypair_with_iCloud(privateKey, publicKey):
    """
    Demo function that "shares" Bob's public-private keypair with iCloud.
    It also shares his symmetric key SK_0.
    """

    print("Bob has shared with iCloud: publicKey={} privateKey={}".format(publicKey, privateKey))

    iCloudKey = (privateKey, publicKey)
    iCloudSecret = b"0" * ((256 // 8))  # 256 bit-long secret; arbitrarily initialize to 0s.

    return None


def send_location_and_index_to_iCloud(index, message):
    """
    Simulates iCloud receiving the message and storing it in its DB.
    """

    print("iCloud has received an anonymous message. It stores it in its records.")
    # iCloudRecords.append(message)
    iCloudRecords[index] = message

    return None


def receive_bobs_publickey(bobKey):
    """
    Simulates a stranger receiving Bob's public key over Bluetooth and
    sending their location information to iCloud.
    """

    print("A stranger's iDevice received Bob's public key!")

    location = "The airport"

    messageToSendToICloud = encrypt_location_with_publickey(location, bobKey)

    lookup_index = SHA256_hash_to_index(bobKey)

    print("A stranger has forwarded location information to iCloud, encrypted using Bob's public key.")

    send_location_and_index_to_iCloud(lookup_index, messageToSendToICloud)

    return None


def broadcast_derived_publickey(publicKey):
    """
    Simulates broadcasting Bob's derived public key P_i over Bluetooth.

    There is a 75% chance that Bob's broadcast reaches no internet-connected iDevices.
    There is a 25% chance that Bob's broadcast reaches an internet-connected iDevice.
    """

    chance = random.randint(1, 4)  # Random int between 1-4 inclusive.
    if (chance == 4):
        receive_bobs_publickey(publicKey)
    else:
        print("Bob didn't find a nearby iDevice.")

    return None


def simulate_find_my():
    """
    The driver for our program.

    This simulates the situation where Bob's phone is lost with no internet,
    and it tries to communicate with iCloud through the iDevice mesh network.
    """

    PHONE_IS_TURNED_ON = True
    PHONE_HAS_INTERNET = False
    currentTime = 0  # Number of minutes Bob's phone has been lost.

    # When Bob first launches his phone and checks the "enable offline
    # discovery" box, Find My generates an EC C-224 private key, shared to
    # all of Bob's other Apple devices.
    privateKey, publicKey = generate_iCloud_keypair()
    share_keypair_with_iCloud(privateKey, publicKey)

    SK0 = iCloudSecret
    currentSK = iCloudSecret
    SKCounter = 1

    # When Bob's phone loses access to the internet, it continuously tries to
    # contact iCloud through other devices.
    while (PHONE_IS_TURNED_ON and not PHONE_HAS_INTERNET):
        print("\nThe current time is {}.".format(currentTime))

        currentSK = get_SK_i(SK0, SKCounter)  # Get SK_i where i = counter
        u, v = compute_u_and_v(currentSK)

        privateDerivedKey, publicDerivedKey = generate_new_keypair(
            currentSK, privateKey, publicKey)
        print("Bob's phone uses its keypair to generate the derived keypair ({}, {})." .format(privateDerivedKey, publicDerivedKey))

        print("Bob's phone broadcasts its derived public key {} over Bluetooth..." .format(publicDerivedKey))
        # Hopefully Bob's phone can transmit its location to iCloud...

        broadcast_derived_publickey(publicDerivedKey)
        print("Bob's phone have performed broadcasting and called receive_bobs_publickey")

        print("Bob's Macbook reads iCloud records to try to find one he can decrypt...")

        foundLocation = bobs_macbook_tries_to_locate_phone()  # Hopefully Bob's macbook finds location info in iCloud...

        if (foundLocation != None):
            print("Bob has located his phone after {} minutes! It was at: {}" .format(currentTime, foundLocation))
            return True

        currentTime += 15
        SKCounter += 1

    return None


if __name__ == "__main__":
    print("Starting simulation...")
    simulate_find_my()
    print("Simulation concluded.")
