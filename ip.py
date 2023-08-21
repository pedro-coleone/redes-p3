from iputils import *
import socket


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self._count = -1

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl -= 1
            
            if ttl <= 0:
                next_hop_2 = self._next_hop(src_addr)

                datagrama_errado = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                checksum2 = calc_checksum(datagrama_errado)

                datagrama_errado = struct.pack('!BBHHHBBHII', (4 << 4) | 5, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, checksum2, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                icmp = struct.pack('!BBHHH', 11, 0, 0, 0, 0)
                checksum3 = calc_checksum(datagrama_errado + icmp)
                icmp = struct.pack('!BBHHH', 11, 0, checksum3, 0, 0)

                datagrama_errado = datagrama_errado + icmp + datagrama[:28]
                self.enlace.enviar(datagrama_errado, next_hop_2)
                return
            
            # Atualizar o campo TTL no datagrama
            datagrama = datagrama[:8] + bytes([ttl]) + datagrama[9:]
            
            # Corrigir o checksum do cabeçalho
            datagrama = datagrama[:10] + b'\x00\x00' + datagrama[12:]
            header_checksum = calc_checksum(datagrama[:20])
            datagrama = datagrama[:10] + struct.pack('!H', header_checksum) + datagrama[12:]
            
            # Obter o próximo salto
            next_hop = self._next_hop(dst_addr)
            
            # Enviar o datagrama para o próximo salto
            self.enlace.enviar(datagrama, next_hop)

            
    def _next_hop(self, dest_addr):
        hop = None
        max_prefix = -1

        (dest_ip,) = struct.unpack("!I", str2addr(dest_addr))

        for cidr, next_hop in self.tabela_hash.items():
            net, prefix = cidr.split('/')
            prefix_len = int(prefix)

            (net_ip,) = struct.unpack("!I", str2addr(net))
            net_mask = 0xFFFFFFFF << (32 - prefix_len)
            net_ip_masked = net_ip & net_mask
            dest_ip_masked = dest_ip & net_mask

            if net_ip_masked == dest_ip_masked and prefix_len > max_prefix:
                max_prefix = prefix_len
                hop = next_hop

        return hop


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco


    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = []
        for item in tabela:
            self.tabela.append({
                'cidr': item[0],
                'next_hop': item[1],
            })

        self.tabela_hash = {item[0]: item[1] for item in tabela}
    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
    
        if next_hop is not None:
            # Montar o cabeçalho IP
            version_ihl = (4 << 4) + 5  # Versão: IPv4, IHL: 5 palavras de 32 bits
            dscp_ecn = 0  # DSCP e ECN ambos definidos como 0
            total_length = 20 + len(segmento)  # Tamanho total do datagrama (20 bytes do cabeçalho IP + tamanho do segmento)
            identification = 0  # Identificação, você pode escolher um valor ou gerar um de forma apropriada
            flags_offset = 0  # Flags e deslocamento, ambos definidos como 0
            ttl = 64  # TTL, ajuste conforme necessário
            proto = IPPROTO_TCP  # Protocolo, definido como TCP
            src_addr = self.meu_endereco  # Endereço IP de origem
            dst_addr = dest_addr  # Endereço IP de destino

            # Montar o cabeçalho IP usando struct.pack
            ip_header = struct.pack('!BBHHHBBH4s4s',
                version_ihl,
                dscp_ecn,
                total_length,
                identification,
                flags_offset,
                ttl,
                proto,
                0,  # Checksum temporário, será calculado depois
                socket.inet_aton(src_addr),
                socket.inet_aton(dst_addr)
            )

            # Calcular o checksum do cabeçalho IP
            checksum = calc_checksum(ip_header)

            # Substituir o campo de checksum no cabeçalho IP
            ip_header = struct.pack('!BBHHHBBH4s4s',
                version_ihl,
                dscp_ecn,
                total_length,
                identification,
                flags_offset,
                ttl,
                proto,
                checksum,
                socket.inet_aton(src_addr),
                socket.inet_aton(dst_addr)
            )

            # Montar o datagrama completo com o cabeçalho IP e o segmento TCP como payload
            datagrama = ip_header + segmento

            # Enviar o datagrama usando self.enlace.enviar
            self.enlace.enviar(datagrama, next_hop)
