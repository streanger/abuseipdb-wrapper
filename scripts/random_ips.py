import random


def random_ipv4():
    """generate random IPv4 address"""
    return ".".join([str(random.randrange(256)) for x in range(4)])


if __name__ == "__main__":
    random_ipv4_list = [random_ipv4() for x in range(10)]
    random_ipv4_space = " ".join(random_ipv4_list)
    random_ipv4_newline = "\n".join(random_ipv4_list)
    print(random_ipv4_space)
