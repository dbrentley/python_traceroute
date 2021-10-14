import random
import socket
import struct
import time


class Tracer(object):
    def __init__(self, dst, hops=20):
        self.dst = dst
        self.hops = hops
        self.ttl = 1

        # Pick up a random port in the range 33434-33534
        self.port = random.choice(range(33434, 33535))

        self.ICMP_ECHO_REQUEST = 8
        self.checksum = 0
        self.own_id = 0
        self.seq_number = 0
        self.packet_size = 55

    def run(self):
        try:
            dst_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}', self.dst, e)

        text = f'traceroute to {self.dst} ({dst_ip}), {self.hops} hops max'

        print(text)

        while True:
            receiver = self.create_receiver()
            sender = self.create_icmp_sender()

            latency, addr = None, None
            start_time = time.time()

            header = struct.pack(
                '!BBHHH', self.ICMP_ECHO_REQUEST, 0, self.checksum, self.own_id, self.seq_number
            )
            pad_bytes = []
            start_val = 0x42
            for i in range(start_val, start_val + self.packet_size):
                pad_bytes += [(i & 0xff)]
            data = bytes(pad_bytes)

            sender.sendto(header + data, (self.dst, self.port))

            hostname = None
            try:
                data, addr = receiver.recvfrom(1024)
                latency = time.time() - start_time
                ip, port = addr
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.timeout:
                pass
            except socket.herror:
                hostname, port = addr
            except socket.error as e:
                raise IOError(f'Socket error: {e}')
            finally:
                receiver.close()
                sender.close()

            if addr:
                ipv = None  # WIP
                # ipv = struct.unpack_from(
                #     "!I", data[0], 0
                # )
                print(f'{self.ttl:<4} {addr[0]:<16} {str(latency)[:5]:<5}ms {ipv} {hostname}')
                if addr[0] == dst_ip or self.ttl > self.hops:
                    break
            else:
                print(f'{self.ttl:<4} *')

            self.ttl += 1
            if self.ttl > self.hops:
                break

            self.seq_number += 1

    def create_receiver(self):
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        try:
            s.bind(('', self.port))
            s.settimeout(3)
        except socket.error as e:
            raise IOError(f'Unable to bind receiver socket: {e}')

        return s

    def create_udp_sender(self):
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP
        )

        s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        s.settimeout(3)

        return s

    def create_icmp_sender(self):
        s = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        s.settimeout(3)

        return s


if __name__ == '__main__':
    tracer = Tracer('example.com')
    tracer.run()
