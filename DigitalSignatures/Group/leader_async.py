import asyncio
import json
import struct
import secrets
from group_signature import load_key, encrypt_1_part_signature, encrypt_2_part_signature, encrypt_3_part_signature, algorithm_fast_pow, compute_lambda_exponent, sha512_function

HOST = '127.0.0.1'
PORT = 55556

async def handle_client(reader, writer, clients, members_pub_keys, lamda, R, T, M, S, pub_key, scrt_key, hash_function):
    p, alpha, N = pub_key["Prime"], pub_key["Alpha"], pub_key["N"]
    z, d = scrt_key["X"], scrt_key["PrivateExponent"]

    try:
        # Получаем данные от клиента
        length_bytes = await reader.readexactly(4)
        length = struct.unpack('!I', length_bytes)[0]
        message_bytes = await reader.readexactly(length)
        data = json.loads(message_bytes.decode('utf-8'))
        print(f"Request from client: {data}")

        if data["Message"]:
            M[0] = data["Message"]
            members_pub_keys.append(data["MemberPublicKey"]["y"])
            R.append(data["R"])
            T.append(data["T"])

            hash_value = hash_function(M[0])
            lamda_i = compute_lambda_exponent(hash_value, data["MemberPublicKey"]["y"], d, hash_function)
            lamda.append(lamda_i)
            clients.append((writer, data["MemberPublicKey"]["id"]))

            # Отправляем подтверждение
            response = {"status": "received", "message": "Data received"}
            response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
            writer.write(struct.pack('!I', len(response_bytes)) + response_bytes)
            await writer.drain()

        if len(clients) == 2:
            # Обрабатываем данные после получения от обоих клиентов
            U = encrypt_1_part_signature(members_pub_keys, lamda, p)
            t = secrets.randbelow(N)
            r = algorithm_fast_pow(alpha, t, p)
            T.append(t)
            R.append(r)
            E, R_sum = encrypt_2_part_signature(hash_value, R, p, U, hash_function)

            for writer, id in clients:
                response = {
                    "status": "success",
                    "lamda": lamda[id],
                    "R": R_sum,
                    "E": E
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                writer.write(struct.pack('!I', len(response_bytes)) + response_bytes)
                await writer.drain()

            for writer, id in clients:
                length_bytes = await reader.readexactly(4)
                length = struct.unpack('!I', length_bytes)[0]
                message_bytes = await reader.readexactly(length)
                data = json.loads(message_bytes.decode('utf-8'))
                s = data["s"]
                lamda_inv = algorithm_fast_pow(lamda[id], -1, p)  # Исправлено на вычисление обратного элемента
                if R[id] != (algorithm_fast_pow(members_pub_keys[id], lamda_inv * E, p) * algorithm_fast_pow(alpha, s, p)) % p:
                    response = {
                        "status": "error",
                        "message": "Server error: Invalid sign part S"
                    }
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    writer.write(struct.pack('!I', len(response_bytes)) + response_bytes)
                    await writer.drain()
                    raise TypeError(f"Invalid sign part \"S\" from member {id}")
                else:
                    S.append(s)

            s = (sum(T) + z * E) % N
            S.append(s)
            S = encrypt_3_part_signature(S, N)

    except Exception as e:
        print(f"Error handling connection: {e}")
        response = {"status": "error", "message": f"Server error: {str(e)}"}
        response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
        writer.write(struct.pack('!I', len(response_bytes)) + response_bytes)
        await writer.drain()

async def server():
    pub_key = load_key("DigitalSignatures/Group/group_keys/leader_public_key.json")
    scrt_key = load_key("DigitalSignatures/Group/group_keys/leader_secret_key.json")
    hash_function = sha512_function

    clients = []
    members_pub_keys = []
    lamda = []
    R = []
    T = []
    M = [""]
    S = []

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, clients, members_pub_keys, lamda, R, T, M, S, pub_key, scrt_key, hash_function),
        HOST, PORT
    )
    print(f"Server listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(server())