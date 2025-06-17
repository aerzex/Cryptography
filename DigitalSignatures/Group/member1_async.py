import asyncio
import json
import struct
import secrets
from group_signature import algorithm_fast_pow, load_key

HOST = '127.0.0.1'
PORT = 55556

async def client(member_id):
    leader_pub_key = load_key("DigitalSignatures/Group/group_keys/leader_public_key.json")
    p, alpha, N = leader_pub_key["Prime"], leader_pub_key["Alpha"], leader_pub_key["N"]
    try:
        pub_key = load_key(f"DigitalSignatures/Group/group_keys/member_{member_id}_public_key.json")
        scrt_key = load_key(f"DigitalSignatures/Group/group_keys/member_{member_id}_secret_key.json")

        reader, writer = await asyncio.open_connection(HOST, PORT)

        t = secrets.randbelow(N)
        r = algorithm_fast_pow(alpha, t, p)
        data = {
            "MemberPublicKey": pub_key,
            "R": r,
            "T": t,
            "Message": "random data" if member_id == 0 else ""
        }
        message = json.dumps(data, ensure_ascii=False).encode('utf-8')
        writer.write(struct.pack('!I', len(message)) + message)
        await writer.drain()

        # Ожидаем подтверждение
        length_bytes = await reader.readexactly(4)
        length = struct.unpack('!I', length_bytes)[0]
        response_bytes = await reader.readexactly(length)
        response = json.loads(response_bytes.decode('utf-8'))
        print(f"Response from leader: {response}")

        if response["status"] == "received":
            # Ожидаем финальный ответ
            length_bytes = await reader.readexactly(4)
            length = struct.unpack('!I', length_bytes)[0]
            response_bytes = await reader.readexactly(length)
            response = json.loads(response_bytes.decode('utf-8'))
            print(f"Final response from leader: {response}")

            if response["status"] == "success":
                lamda = response["lamda"]
                R = response["R"]
                E = response["E"]
                s = (t + scrt_key["x"] * lamda + E) % p
                data = {"s": s}
                message = json.dumps(data, ensure_ascii=False).encode('utf-8')
                writer.write(struct.pack('!I', len(message)) + message)
                await writer.drain()

    except Exception as e:
        print(f"Client error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    member_id = 0 
    asyncio.run(client(member_id))