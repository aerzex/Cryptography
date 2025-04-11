from rsa import encrypt, decrypt, generate_keys


def main():
    # size = int(input("Enter size of N: "))
    message_en = "If I don’t like a thing, I don’t like it, that’s all; and there is no reason under the sun why I should ape a liking for it just because the majority of my fellow-creatures like it, or make believe they like it. I can’t follow the fashions in the things I like or dislike."
    message_ru = "Если мне что-то не нравится, значит, не нравится, и все тут; так с какой стати, спрашивается, я стану делать вид, будто мне это нравится, только потому, что большинству моих соплеменников это нравится или они воображают, что нравится. Не могу я что-то любить или не любить по велению моды."
    # pub_key, scrt_key = generate_keys(size)
    password = "P@ssw0rd"
    enc_message = encrypt(message_ru)
    dec_message = decrypt(password, enc_message)
    print(enc_message)
    print(dec_message)


if __name__ == "__main__":
    main()
