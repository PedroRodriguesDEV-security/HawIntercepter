#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>

#define HAVE_REMOTE
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Pacote com tamanho:  [%d]\n", header->len);
    for (int i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n\n");
}

int main() {
    pcap_if_t *alldevs, *device;
    pcap_t *HANDLE;
    char errbuf[PCAP_ERRBUF_SIZE];


    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erro ao encontrar dispositivos: %s\n", errbuf);
        return 1;
    }

    printf("Dispositivos disponíveis:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s\n", device->name);
    }

    device = alldevs;
    if (device == NULL) {
        fprintf(stderr, "Nenhum dispositivo encontrado.\n");
        return 1;
    }

    // Abre o dispositivo para captura
    HANDLE = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (HANDLE == NULL) {
        fprintf(stderr, "Não foi possível abrir o dispositivo %s: %s\n", device->name, errbuf);
        return 1;
    }

    pcap_loop(HANDLE, 10, packet_handler, NULL);

    pcap_close(HANDLE);
    pcap_freealldevs(alldevs);

    return 0;
}
