import sys
import re
import socket


def print_error(msg):
    print(msg, file=sys.stderr)


def print_log(msg):
    print(msg)


def get_arg_port():
    """
    Checks args and extracts PORT number
    Other arguments are not ignored, but considered as error.
    """

    if len(sys.argv) != 2:
        print_error("Argument PORT is required.")
        sys.exit(-1)

    port_and_num = sys.argv[1].split("=")
    if len(port_and_num) == 2 and port_and_num[0] == "PORT" and port_and_num[1].isnumeric():
        return int(port_and_num[1])
    else:
        print_error("Can not find PORT number.")
        sys.exit(-1)


class Responder:
    """
    Excepts requests, resolves it and returns answer
    """
    WINDOWS_LINE_ENDING = '\r\n'
    UNIX_LINE_ENDING = '\n'

    def __init__(self):
        self.response_header = ""
        self.response_msg = ""
        self.request_data = ""

    def clean_last_data(self):
        self.response_header = ""
        self.response_msg = ""

    def set_OK_header(self):
        self.response_header = "HTTP/1.1 200 OK\nContent-Type: text/plain\n"

    def set_BAD_REQUEST_header(self):
        self.response_header = "HTTP/1.1 400 Bad Request\nContent-Length:0\n\n"
        print_error(f'Bad request format:\n{self.request_data}')

    def set_METHOD_NOT_ALLOWED_header(self):
        self.response_header = "HTTP/1.1 405 Method Not Allowed\nContent-Length:0\n\n"
        print_error(f"Unknown method:\n{self.request_data}")

    def set_NOT_FOUND_header(self):
        self.response_header = "HTTP/1.1 404 Not Found\nContent-Length:0\n\n"
        print_error(f"Did not found any response on request:\n{self.request_data}")

    def set_msg(self, answer):
        answer = answer + '\n'
        msg_len = len(answer.encode('ascii'))
        self.response_header = self.response_header + f"Content-Length:{msg_len}\n\n"
        self.response_msg = answer

        print_log(f"Response:\n{answer}")

    def translate_domain(self, domain: str, type_r: str):
        """Resolves name or address
        >>> s.translate_domain('apple.com', 'A')
        'apple.com:A=17.172.224.47'
        >>> s.translate_domain('17.172.224.47', 'PTR')
        '17.172.224.47:PTR=appleid.org'
        >>> s.translate_domain('17.172.224', 'PTR')
        """

        translation = None
        try:
            if type_r == 'A':
                translation = socket.gethostbyname(domain)
            elif type_r == 'PTR':
                translation = socket.gethostbyaddr(domain)[0]
            else:
                return None

        except socket.error:
            return None

        return f'{domain}:{type_r}={translation}'

    def check_request_line(self, line, type_r):
        """
        >>> s.check_request_line('www.fit.vutbr.cz', 'A')
        True
        >>> s.check_request_line('147.229.14.131', 'PTR')
        True
        >>> s.check_request_line('www.fit.vutbr.cz', 'PTR')
        False
        >>> s.check_request_line('147.229.14.131', 'A')
        False
        """

        if not line or not type_r:
            return False

        ip_n = re.compile('^[\d.]+$')
        name_n = re.compile('^[\w.\/]+$')
        a_type = re.compile('^(?:A)$')
        ptr_type = re.compile('^(?:PTR)$')

        if a_type.search(type_r):
            if ip_n.search(line):
                return False
            elif name_n.search(line):
                return True

        elif ptr_type.search(type_r):
            if name_n.search(line) and not ip_n.search(line):
                return False
            elif ip_n.search(line):
                return True

        return False

    def split_get_request(self, get_request: str) -> list:
        """Returns a tupple of splitted get request
        >>> s.split_get_request('GET /resolve?name=www.fit.vutbr.cz&type=A HTTP/1.1')
        ['www.fit.vutbr.cz', 'A']
        >>> s.split_get_request('GET /resolve?name=www.fit.vutbr.cz')
        [None, None]
        """

        pattern = re.compile(
            '''(?:GET \/resolve\?name=)([.a-zA-Z0-9/]+)(?:&type=)((?:A)|(?:PTR))(?: )(?:HTTP\/[\d.]+)(?:\s)*$''')
        m = pattern.match(get_request)

        if m:
            groups = [g for g in m.groups() if g]
            if groups and len(groups) == 2:
                return groups

        return [None, None]

    def process_get(self):
        (first_line, other_lines) = self.request_data.split("\n", 1)
        (name, type_r) = self.split_get_request(first_line)

        if not self.check_request_line(name, type_r):
            self.set_BAD_REQUEST_header()
            return

        resolution = self.translate_domain(name, type_r)
        if resolution:
            self.set_OK_header()
            self.set_msg(resolution)
        else:
            self.set_NOT_FOUND_header()

    def check_post_header(self, header):
        return bool(re.search('^POST \/dns-query HTTP\/[\d.]+\s*$', header))

    def process_post(self):

        headers, lines = self.request_data.split("\n\n", 1)
        header = headers.splitlines()[0]
        lines = lines.rstrip().splitlines()

        if not self.check_post_header(header):
            self.set_BAD_REQUEST_header()
            return

        slitted_lines = [line.rstrip().rsplit(':', 1) for line in lines]
        likes_ok = all(
            len(name_type) == 2 and self.check_request_line(name_type[0], name_type[1]) for name_type in slitted_lines)

        if not likes_ok:
            self.set_BAD_REQUEST_header()
            return

        responses = [self.translate_domain(*slitted_line) for slitted_line in slitted_lines]
        responses = [response for response in responses if response]

        if not responses:
            self.set_NOT_FOUND_header()
            return

        joined_responses = '\n'.join(responses)

        self.set_OK_header()
        self.set_msg(joined_responses)

    def response(self, request_data: bytes) -> bytes:
        self.clean_last_data()

        self.request_data = request_data.decode().replace(self.WINDOWS_LINE_ENDING, self.UNIX_LINE_ENDING)

        if self.request_data.startswith("GET"):
            self.process_get()
        elif self.request_data.startswith("POST"):
            self.process_post()
        else:
            self.set_NOT_FOUND_header()

        return (self.response_header + self.response_msg).encode('ascii')


class Server:

    def run(self, port):
        resp = Responder()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as welcome_socket:
            welcome_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            welcome_socket.bind(("", port))
            welcome_socket.listen()

            print_log(f'Server is running on port: {port}')

            while True:
                connection_socket, client_address = welcome_socket.accept()

                with connection_socket:
                    print_log(f'\n** Connected to: {client_address[0]}, {client_address[1]}')
                    while True:
                        request_data = connection_socket.recv(2048)
                        if not request_data:
                            break

                        response_data = resp.response(request_data)
                        connection_socket.sendall(response_data)


def main():
    server_port = get_arg_port()

    print(type(server_port))

    server = Server()
    server.run(server_port)


if __name__ == '__main__':
    main()

    # import doctest
    # doctest.testmod(extraglobs={'s': Responder()})
